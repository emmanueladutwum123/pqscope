import { createHash } from 'crypto';

export function Digest({ text }: { text: string }) {
  const d = createHash('sha1').update(text).digest('hex');
  return <span>{d}</span>;
}
