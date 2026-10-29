import { describe, expect, it, vi } from 'vitest';
import {
  YoxallismusCipher,
  YoxallismusV1UnrecoverableError,
  YOXALLISMUS_V1_DEPRECATION,
} from '../src/yoxallismus.js';

describe('YoxallismusCipher (deprecated, YOXALL-2026-003)', () => {
  it('warns once per process when constructed', () => {
    const spy = vi.spyOn(process, 'emitWarning').mockImplementation(() => {});
    new YoxallismusCipher({ key: 'k' });
    new YoxallismusCipher({ key: 'k' });
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(YOXALLISMUS_V1_DEPRECATION, { type: 'DeprecationWarning', code: 'HORD_YOXALLISMUS_V1' });
    spy.mockRestore();
  });

  it('lock()/encode() still produce v1 output', () => {
    const c = new YoxallismusCipher({ key: 'k', tumblers: 7 });
    const locked = c.lock('sensitive');
    expect(locked.subarray(0, 4).toString()).toBe('YXLS');
    expect(locked[4]).toBe(1);
    expect(typeof c.encode('sensitive')).toBe('string');
  });

  it('unlock()/decode() throw instead of returning wrong bytes', () => {
    const c = new YoxallismusCipher({ key: 'k' });
    expect(() => c.unlock(c.lock('sensitive'))).toThrow(YoxallismusV1UnrecoverableError);
    expect(() => c.decode(c.encode('sensitive'))).toThrow(/YOXALL-2026-003/);
  });

  it('non-v1 input still gets the bad-magic error', () => {
    expect(() => new YoxallismusCipher({ key: 'k' }).unlock(Buffer.from('not a payload'))).toThrow(/bad magic/);
  });
});
