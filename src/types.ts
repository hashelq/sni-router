export interface MitmRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Buffer;
  hostname: string;
}

export interface MitmResponse {
  write(data: string | Buffer): boolean;
  end(): void;
}

export type MitmHandler = (req: MitmRequest, res: MitmResponse) => void | Promise<void>;
