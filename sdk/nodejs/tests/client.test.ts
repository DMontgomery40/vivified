import { VivifiedClient } from '../src';

test('client exposes required methods', async () => {
  const c = new VivifiedClient('http://localhost:8000');
  expect(typeof (c as any).publish_event).toBe('function');
  expect(typeof (c as any).subscribe).toBe('function');
  expect(typeof (c as any).call_plugin).toBe('function');
  expect(typeof (c as any).call_external).toBe('function');
  expect(typeof (c as any).get_config).toBe('function');
  expect(typeof (c as any).set_config).toBe('function');
});

