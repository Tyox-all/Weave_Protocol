/**
 * Witan - Communication Bus
 * 
 * Agent-to-agent messaging, pub/sub channels, and broadcast communication
 * for coordinated multi-agent AI systems.
 */

import * as crypto from 'crypto';

// =============================================================================
// Types
// =============================================================================

export type MessagePriority = 'critical' | 'high' | 'normal' | 'low';
export type MessageStatus = 'pending' | 'delivered' | 'acknowledged' | 'failed' | 'expired';
export type ChannelType = 'broadcast' | 'topic' | 'direct' | 'group';

export interface Message {
  id: string;
  thread_id?: string;
  
  // Routing
  from: string;
  to: string | string[];  // Agent ID(s) or channel name
  channel?: string;
  reply_to?: string;  // Message ID being replied to
  
  // Content
  type: string;
  payload: any;
  
  // Delivery
  priority: MessagePriority;
  status: MessageStatus;
  require_ack: boolean;
  ttl_ms?: number;
  
  // Tracking
  created_at: Date;
  delivered_at?: Date;
  acknowledged_at?: Date;
  acknowledgments: Map<string, Date>;
  
  // Verification
  hash: string;
  signature: string;
}

export interface Channel {
  id: string;
  name: string;
  type: ChannelType;
  
  // Membership
  owner: string;
  members: Set<string>;
  
  // Config
  config: ChannelConfig;
  
  // Stats
  created_at: Date;
  message_count: number;
  last_message_at?: Date;
  
  metadata: Record<string, any>;
}

export interface ChannelConfig {
  max_members?: number;
  require_membership: boolean;
  persist_messages: boolean;
  max_message_history: number;
  rate_limit_per_minute?: number;
  allowed_message_types?: string[];
}

export interface Subscription {
  id: string;
  subscriber_id: string;
  channel_id: string;
  filter?: MessageFilter;
  created_at: Date;
  last_received_at?: Date;
  message_count: number;
}

export interface MessageFilter {
  types?: string[];
  priorities?: MessagePriority[];
  from?: string[];
  custom?: (message: Message) => boolean;
}

export interface DeliveryReceipt {
  message_id: string;
  recipient_id: string;
  status: 'delivered' | 'acknowledged' | 'failed';
  timestamp: Date;
  error?: string;
}

export interface BusConfig {
  default_ttl_ms: number;
  max_message_size_bytes: number;
  max_pending_messages: number;
  delivery_retry_count: number;
  delivery_retry_delay_ms: number;
  persist_messages: boolean;
}

export interface BusEvent {
  type: 'message_sent' | 'message_delivered' | 'message_acknowledged' | 'message_expired' | 'channel_created' | 'member_joined' | 'member_left';
  timestamp: Date;
  details: Record<string, any>;
}

// =============================================================================
// Communication Bus
// =============================================================================

export class CommunicationBus {
  private messages: Map<string, Message> = new Map();
  private channels: Map<string, Channel> = new Map();
  private subscriptions: Map<string, Subscription> = new Map();
  private subscriberChannels: Map<string, Set<string>> = new Map();  // subscriber -> channel IDs
  private channelHistory: Map<string, string[]> = new Map();  // channel -> message IDs
  private pendingDeliveries: Map<string, Message[]> = new Map();  // recipient -> messages
  private messageHandlers: Map<string, ((message: Message) => Promise<void>)[]> = new Map();  // subscriber -> handlers
  private signingKey: Buffer;
  private config: BusConfig;
  private eventCallbacks: ((event: BusEvent) => void)[] = [];
  
  constructor(signingKey: string, config?: Partial<BusConfig>) {
    this.signingKey = crypto.scryptSync(signingKey, 'witan-bus', 32);
    this.config = {
      default_ttl_ms: 300000,  // 5 minutes
      max_message_size_bytes: 1048576,  // 1MB
      max_pending_messages: 1000,
      delivery_retry_count: 3,
      delivery_retry_delay_ms: 1000,
      persist_messages: true,
      ...config,
    };
    
    // Create default broadcast channel
    this.createChannel({
      name: 'broadcast',
      type: 'broadcast',
      owner: 'system',
      config: { require_membership: false, persist_messages: true, max_message_history: 100 }
    });
    
    // Start expiry checker
    setInterval(() => this.checkExpiredMessages(), 10000);
  }
  
  // ===========================================================================
  // Messaging
  // ===========================================================================
  
  /**
   * Send a direct message
   */
  async send(params: {
    from: string;
    to: string | string[];
    type: string;
    payload: any;
    priority?: MessagePriority;
    require_ack?: boolean;
    ttl_ms?: number;
    reply_to?: string;
    thread_id?: string;
  }): Promise<Message> {
    // Validate size
    const payloadSize = JSON.stringify(params.payload).length;
    if (payloadSize > this.config.max_message_size_bytes) {
      throw new Error(`Message payload exceeds maximum size (${this.config.max_message_size_bytes} bytes)`);
    }
    
    const id = `msg_${crypto.randomUUID()}`;
    const now = new Date();
    
    const hash = crypto.createHash('sha256')
      .update(JSON.stringify({ from: params.from, to: params.to, type: params.type, payload: params.payload }))
      .digest('hex');
    
    const message: Message = {
      id,
      thread_id: params.thread_id,
      
      from: params.from,
      to: params.to,
      reply_to: params.reply_to,
      
      type: params.type,
      payload: params.payload,
      
      priority: params.priority || 'normal',
      status: 'pending',
      require_ack: params.require_ack || false,
      ttl_ms: params.ttl_ms || this.config.default_ttl_ms,
      
      created_at: now,
      acknowledgments: new Map(),
      
      hash,
      signature: this.sign(hash),
    };
    
    this.messages.set(id, message);
    
    // Deliver to recipients
    const recipients = Array.isArray(params.to) ? params.to : [params.to];
    await this.deliverToRecipients(message, recipients);
    
    this.emitEvent({
      type: 'message_sent',
      timestamp: now,
      details: { message_id: id, from: params.from, to: params.to, type: params.type }
    });
    
    return message;
  }
  
  /**
   * Send to a channel
   */
  async publish(params: {
    from: string;
    channel: string;
    type: string;
    payload: any;
    priority?: MessagePriority;
    require_ack?: boolean;
    thread_id?: string;
  }): Promise<Message> {
    const channel = this.channels.get(params.channel);
    if (!channel) throw new Error(`Channel ${params.channel} not found`);
    
    // Check membership
    if (channel.config.require_membership && !channel.members.has(params.from)) {
      throw new Error(`${params.from} is not a member of channel ${params.channel}`);
    }
    
    // Check allowed types
    if (channel.config.allowed_message_types?.length) {
      if (!channel.config.allowed_message_types.includes(params.type)) {
        throw new Error(`Message type ${params.type} not allowed in channel ${params.channel}`);
      }
    }
    
    const recipients = Array.from(channel.members).filter(m => m !== params.from);
    
    const message = await this.send({
      ...params,
      to: recipients,
    });
    
    message.channel = params.channel;
    
    // Update channel stats
    channel.message_count++;
    channel.last_message_at = new Date();
    
    // Store in history
    if (channel.config.persist_messages) {
      const history = this.channelHistory.get(params.channel) || [];
      history.push(message.id);
      
      // Trim history
      if (history.length > channel.config.max_message_history) {
        history.shift();
      }
      
      this.channelHistory.set(params.channel, history);
    }
    
    return message;
  }
  
  /**
   * Broadcast to all agents
   */
  async broadcast(params: {
    from: string;
    type: string;
    payload: any;
    priority?: MessagePriority;
    exclude?: string[];
  }): Promise<Message> {
    const broadcastChannel = this.channels.get('broadcast')!;
    let recipients = Array.from(broadcastChannel.members);
    
    if (params.exclude) {
      recipients = recipients.filter(r => !params.exclude!.includes(r));
    }
    
    recipients = recipients.filter(r => r !== params.from);
    
    return this.send({
      from: params.from,
      to: recipients,
      type: params.type,
      payload: params.payload,
      priority: params.priority || 'high',
    });
  }
  
  /**
   * Acknowledge message receipt
   */
  async acknowledge(messageId: string, recipientId: string): Promise<void> {
    const message = this.messages.get(messageId);
    if (!message) throw new Error(`Message ${messageId} not found`);
    
    message.acknowledgments.set(recipientId, new Date());
    
    // Check if all recipients acknowledged
    const recipients = Array.isArray(message.to) ? message.to : [message.to];
    const allAcked = recipients.every(r => message.acknowledgments.has(r));
    
    if (allAcked) {
      message.status = 'acknowledged';
      message.acknowledged_at = new Date();
    }
    
    this.emitEvent({
      type: 'message_acknowledged',
      timestamp: new Date(),
      details: { message_id: messageId, recipient_id: recipientId }
    });
  }
  
  /**
   * Get pending messages for a recipient
   */
  async receive(recipientId: string, options?: {
    types?: string[];
    priorities?: MessagePriority[];
    limit?: number;
    mark_delivered?: boolean;
  }): Promise<Message[]> {
    let pending = this.pendingDeliveries.get(recipientId) || [];
    
    // Apply filters
    if (options?.types) {
      pending = pending.filter(m => options.types!.includes(m.type));
    }
    if (options?.priorities) {
      pending = pending.filter(m => options.priorities!.includes(m.priority));
    }
    
    // Sort by priority and time
    const priorityOrder: MessagePriority[] = ['critical', 'high', 'normal', 'low'];
    pending.sort((a, b) => {
      const pa = priorityOrder.indexOf(a.priority);
      const pb = priorityOrder.indexOf(b.priority);
      if (pa !== pb) return pa - pb;
      return a.created_at.getTime() - b.created_at.getTime();
    });
    
    // Apply limit
    if (options?.limit) {
      pending = pending.slice(0, options.limit);
    }
    
    // Mark as delivered
    if (options?.mark_delivered !== false) {
      for (const msg of pending) {
        if (msg.status === 'pending') {
          msg.status = 'delivered';
          msg.delivered_at = new Date();
        }
      }
      
      // Remove from pending
      const remaining = (this.pendingDeliveries.get(recipientId) || [])
        .filter(m => !pending.includes(m));
      this.pendingDeliveries.set(recipientId, remaining);
    }
    
    return pending;
  }
  
  /**
   * Reply to a message
   */
  async reply(messageId: string, params: {
    from: string;
    type: string;
    payload: any;
  }): Promise<Message> {
    const original = this.messages.get(messageId);
    if (!original) throw new Error(`Message ${messageId} not found`);
    
    return this.send({
      from: params.from,
      to: original.from,
      type: params.type,
      payload: params.payload,
      reply_to: messageId,
      thread_id: original.thread_id,
    });
  }
  
  // ===========================================================================
  // Channels
  // ===========================================================================
  
  /**
   * Create a channel
   */
  async createChannel(params: {
    name: string;
    type: ChannelType;
    owner: string;
    config?: Partial<ChannelConfig>;
    initial_members?: string[];
    metadata?: Record<string, any>;
  }): Promise<Channel> {
    if (this.channels.has(params.name)) {
      throw new Error(`Channel ${params.name} already exists`);
    }
    
    const channel: Channel = {
      id: `ch_${crypto.randomUUID()}`,
      name: params.name,
      type: params.type,
      
      owner: params.owner,
      members: new Set([params.owner, ...(params.initial_members || [])]),
      
      config: {
        require_membership: true,
        persist_messages: true,
        max_message_history: 1000,
        ...params.config,
      },
      
      created_at: new Date(),
      message_count: 0,
      
      metadata: params.metadata || {},
    };
    
    this.channels.set(params.name, channel);
    this.channelHistory.set(params.name, []);
    
    // Update subscriber mappings
    for (const member of channel.members) {
      const channels = this.subscriberChannels.get(member) || new Set();
      channels.add(params.name);
      this.subscriberChannels.set(member, channels);
    }
    
    this.emitEvent({
      type: 'channel_created',
      timestamp: new Date(),
      details: { channel: params.name, owner: params.owner, type: params.type }
    });
    
    return channel;
  }
  
  /**
   * Join a channel
   */
  async joinChannel(channelName: string, memberId: string): Promise<void> {
    const channel = this.channels.get(channelName);
    if (!channel) throw new Error(`Channel ${channelName} not found`);
    
    if (channel.config.max_members && channel.members.size >= channel.config.max_members) {
      throw new Error(`Channel ${channelName} is full`);
    }
    
    channel.members.add(memberId);
    
    const channels = this.subscriberChannels.get(memberId) || new Set();
    channels.add(channelName);
    this.subscriberChannels.set(memberId, channels);
    
    this.emitEvent({
      type: 'member_joined',
      timestamp: new Date(),
      details: { channel: channelName, member: memberId }
    });
  }
  
  /**
   * Leave a channel
   */
  async leaveChannel(channelName: string, memberId: string): Promise<void> {
    const channel = this.channels.get(channelName);
    if (!channel) throw new Error(`Channel ${channelName} not found`);
    
    channel.members.delete(memberId);
    
    const channels = this.subscriberChannels.get(memberId);
    if (channels) {
      channels.delete(channelName);
    }
    
    this.emitEvent({
      type: 'member_left',
      timestamp: new Date(),
      details: { channel: channelName, member: memberId }
    });
  }
  
  /**
   * Get channel info
   */
  getChannel(name: string): Channel | undefined {
    return this.channels.get(name);
  }
  
  /**
   * List channels for a member
   */
  getChannelsForMember(memberId: string): Channel[] {
    const channelNames = this.subscriberChannels.get(memberId) || new Set();
    return Array.from(channelNames).map(n => this.channels.get(n)!).filter(Boolean);
  }
  
  /**
   * Get channel message history
   */
  getChannelHistory(channelName: string, limit?: number): Message[] {
    const history = this.channelHistory.get(channelName) || [];
    const messageIds = limit ? history.slice(-limit) : history;
    return messageIds.map(id => this.messages.get(id)!).filter(Boolean);
  }
  
  // ===========================================================================
  // Subscriptions
  // ===========================================================================
  
  /**
   * Subscribe to messages with handler
   */
  subscribe(subscriberId: string, handler: (message: Message) => Promise<void>, filter?: MessageFilter): () => void {
    const handlers = this.messageHandlers.get(subscriberId) || [];
    
    const wrappedHandler = async (message: Message) => {
      // Apply filter
      if (filter) {
        if (filter.types && !filter.types.includes(message.type)) return;
        if (filter.priorities && !filter.priorities.includes(message.priority)) return;
        if (filter.from && !filter.from.includes(message.from)) return;
        if (filter.custom && !filter.custom(message)) return;
      }
      
      await handler(message);
    };
    
    handlers.push(wrappedHandler);
    this.messageHandlers.set(subscriberId, handlers);
    
    // Auto-join broadcast channel
    const broadcastChannel = this.channels.get('broadcast');
    if (broadcastChannel && !broadcastChannel.members.has(subscriberId)) {
      broadcastChannel.members.add(subscriberId);
    }
    
    // Return unsubscribe function
    return () => {
      const currentHandlers = this.messageHandlers.get(subscriberId) || [];
      const index = currentHandlers.indexOf(wrappedHandler);
      if (index !== -1) currentHandlers.splice(index, 1);
    };
  }
  
  /**
   * Register an agent on the bus
   */
  async registerAgent(agentId: string): Promise<void> {
    // Join broadcast channel
    const broadcastChannel = this.channels.get('broadcast');
    if (broadcastChannel) {
      broadcastChannel.members.add(agentId);
    }
    
    // Initialize pending queue
    if (!this.pendingDeliveries.has(agentId)) {
      this.pendingDeliveries.set(agentId, []);
    }
  }
  
  /**
   * Unregister an agent
   */
  async unregisterAgent(agentId: string): Promise<void> {
    // Leave all channels
    const channels = this.subscriberChannels.get(agentId) || new Set();
    for (const channelName of channels) {
      const channel = this.channels.get(channelName);
      if (channel) {
        channel.members.delete(agentId);
      }
    }
    
    this.subscriberChannels.delete(agentId);
    this.pendingDeliveries.delete(agentId);
    this.messageHandlers.delete(agentId);
  }
  
  // ===========================================================================
  // Private Methods
  // ===========================================================================
  
  private async deliverToRecipients(message: Message, recipients: string[]): Promise<void> {
    for (const recipientId of recipients) {
      // Add to pending queue
      const pending = this.pendingDeliveries.get(recipientId) || [];
      
      // Check queue limit
      if (pending.length >= this.config.max_pending_messages) {
        // Remove oldest low-priority message
        const lowPriorityIndex = pending.findIndex(m => m.priority === 'low');
        if (lowPriorityIndex !== -1) {
          pending.splice(lowPriorityIndex, 1);
        } else {
          pending.shift();  // Remove oldest
        }
      }
      
      pending.push(message);
      this.pendingDeliveries.set(recipientId, pending);
      
      // Invoke handlers if any
      const handlers = this.messageHandlers.get(recipientId) || [];
      for (const handler of handlers) {
        try {
          await handler(message);
        } catch (e) {
          // Handler error, continue
        }
      }
    }
    
    this.emitEvent({
      type: 'message_delivered',
      timestamp: new Date(),
      details: { message_id: message.id, recipients }
    });
  }
  
  private checkExpiredMessages(): void {
    const now = Date.now();
    
    for (const [id, message] of this.messages) {
      if (message.status === 'pending' || message.status === 'delivered') {
        if (message.ttl_ms && (now - message.created_at.getTime()) > message.ttl_ms) {
          message.status = 'expired';
          
          this.emitEvent({
            type: 'message_expired',
            timestamp: new Date(),
            details: { message_id: id }
          });
        }
      }
    }
  }
  
  private sign(data: string): string {
    const hmac = crypto.createHmac('sha256', this.signingKey);
    hmac.update(data);
    return hmac.digest('hex');
  }
  
  private emitEvent(event: BusEvent): void {
    for (const cb of this.eventCallbacks) {
      try {
        cb(event);
      } catch (e) {
        // Ignore
      }
    }
  }
  
  /**
   * Subscribe to bus events
   */
  onEvent(callback: (event: BusEvent) => void): () => void {
    this.eventCallbacks.push(callback);
    return () => {
      const index = this.eventCallbacks.indexOf(callback);
      if (index !== -1) this.eventCallbacks.splice(index, 1);
    };
  }
  
  /**
   * Get statistics
   */
  getStats(): {
    total_messages: number;
    pending_messages: number;
    channels: number;
    registered_agents: number;
  } {
    let pendingCount = 0;
    for (const pending of this.pendingDeliveries.values()) {
      pendingCount += pending.length;
    }
    
    return {
      total_messages: this.messages.size,
      pending_messages: pendingCount,
      channels: this.channels.size,
      registered_agents: this.pendingDeliveries.size,
    };
  }
}

export default CommunicationBus;
