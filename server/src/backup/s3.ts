import crypto from "crypto";
import fs from "fs";
import { XMLParser } from "fast-xml-parser";
import { outboundFetch } from "../lib/outbound";

// The three S3 calls a scheduled backup needs - put an object, list a
// prefix, delete an object - signed with AWS Signature Version 4.
//
// Written here rather than pulling in the AWS SDK: SigV4 is a short,
// precisely specified procedure (and checked against AWS's own published
// example in s3.test.ts), while the SDK is a large dependency tree for
// three requests. Going through outboundFetch also means the configured
// proxy and the uploaded CA bundle apply, which the SDK would bypass - an
// on-premises MinIO behind a private CA is a normal target.

export interface S3Config {
  // e.g. https://s3.eu-central-1.amazonaws.com or https://minio.internal:9000
  endpoint: string;
  region: string;
  bucket: string;
  accessKey: string;
  secretKey: string;
  // https://host/bucket/key rather than https://bucket.host/key. MinIO and
  // most self-hosted stores need it; AWS accepts both.
  pathStyle: boolean;
}

export interface SignInput {
  method: string;
  url: URL;
  headers: Record<string, string>;
  payloadHash: string;
  accessKey: string;
  secretKey: string;
  region: string;
  service?: string;
  now?: Date;
}

const hmac = (key: crypto.BinaryLike, data: string) => crypto.createHmac("sha256", key).update(data, "utf8").digest();
const sha256Hex = (data: string | Buffer) => crypto.createHash("sha256").update(data).digest("hex");

// RFC 3986 encoding as SigV4 requires it: everything but unreserved
// characters, and "/" kept in paths.
function uriEncode(value: string, keepSlash: boolean): string {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/%2F/g, keepSlash ? "/" : "%2F");
}

/** Returns the headers to send, Authorization included. */
export function signRequest(input: SignInput): Record<string, string> {
  const now = input.now ?? new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const day = amzDate.slice(0, 8);
  const service = input.service ?? "s3";

  const headers: Record<string, string> = {
    ...input.headers,
    host: input.url.host,
    "x-amz-content-sha256": input.payloadHash,
    "x-amz-date": amzDate,
  };
  const names = Object.keys(headers)
    .map((h) => h.toLowerCase())
    .sort();
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  const canonicalHeaders = names.map((n) => `${n}:${String(lower[n]).trim().replace(/\s+/g, " ")}\n`).join("");
  const signedHeaders = names.join(";");

  const query = [...input.url.searchParams.entries()]
    .map(([k, v]) => [uriEncode(k, false), uriEncode(v, false)])
    .sort(([a, x], [b, y]) => (a === b ? (x < y ? -1 : 1) : a < b ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
  // The path arrives already percent-encoded from URL; decode and
  // re-encode so it is encoded exactly once, the SigV4 way.
  const path = uriEncode(decodeURIComponent(input.url.pathname), true);

  const canonicalRequest = [input.method, path, query, canonicalHeaders, signedHeaders, input.payloadHash].join("\n");
  const scope = `${day}/${input.region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${input.secretKey}`, day), input.region), service), "aws4_request");
  const signature = crypto.createHmac("sha256", signingKey).update(stringToSign, "utf8").digest("hex");

  return {
    ...headers,
    authorization: `AWS4-HMAC-SHA256 Credential=${input.accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

function objectUrl(cfg: S3Config, key: string): URL {
  const base = new URL(cfg.endpoint);
  const encodedKey = key.split("/").map((p) => encodeURIComponent(p)).join("/");
  if (cfg.pathStyle) {
    return new URL(`${base.origin}${base.pathname.replace(/\/$/, "")}/${encodeURIComponent(cfg.bucket)}/${encodedKey}`);
  }
  return new URL(`${base.protocol}//${cfg.bucket}.${base.host}${base.pathname.replace(/\/$/, "")}/${encodedKey}`);
}

async function send(cfg: S3Config, method: string, url: URL, ca: string[] | undefined, extra: {
  headers?: Record<string, string>;
  payloadHash?: string;
  bodyStream?: NodeJS.ReadableStream;
  contentLength?: number;
}): Promise<Response> {
  const headers = signRequest({
    method,
    url,
    headers: extra.headers ?? {},
    payloadHash: extra.payloadHash ?? sha256Hex(""),
    accessKey: cfg.accessKey,
    secretKey: cfg.secretKey,
    region: cfg.region,
  });
  // host is part of the signature but set by the transport itself.
  delete headers.host;
  return outboundFetch(url, { method, headers }, {
    ca,
    bodyStream: extra.bodyStream,
    contentLength: extra.contentLength,
    // An upload is measured in inactivity, not total duration - a slow
    // link moving a large archive steadily is fine.
    timeoutMs: 120_000,
  });
}

async function failure(res: Response, what: string): Promise<Error> {
  const text = await res.text().catch(() => "");
  const code = /<Code>([^<]+)<\/Code>/.exec(text)?.[1];
  const message = /<Message>([^<]+)<\/Message>/.exec(text)?.[1];
  return new Error(`${what} failed: ${res.status}${code ? ` ${code}` : ""}${message ? ` - ${message}` : ""}`);
}

// A single PUT carries at most 5 GiB on AWS; larger needs multipart upload,
// which is not implemented. Refused up front with the reason rather than
// failing after uploading 5 GiB.
export const MAX_SINGLE_PUT_BYTES = 5 * 1024 ** 3;

export async function putObjectFromFile(cfg: S3Config, key: string, filePath: string, ca?: string[]): Promise<void> {
  const size = fs.statSync(filePath).size;
  if (size > MAX_SINGLE_PUT_BYTES) {
    throw new Error(`the archive is ${Math.round(size / 1024 ** 3)} GiB, more than the 5 GiB a single S3 upload can carry`);
  }
  // Hashed first rather than sent UNSIGNED-PAYLOAD: every S3-compatible
  // store accepts a real payload hash, not all accept the unsigned form
  // over plain http, and the file is local so reading it twice is cheap.
  const hash = crypto.createHash("sha256");
  for await (const chunk of fs.createReadStream(filePath)) hash.update(chunk as Buffer);
  const res = await send(cfg, "PUT", objectUrl(cfg, key), ca, {
    headers: { "content-type": "application/gzip" },
    payloadHash: hash.digest("hex"),
    bodyStream: fs.createReadStream(filePath),
    contentLength: size,
  });
  if (!res.ok) throw await failure(res, "upload");
  await res.arrayBuffer().catch(() => undefined);
}

export async function listObjects(cfg: S3Config, prefix: string, ca?: string[]): Promise<string[]> {
  const keys: string[] = [];
  let token: string | undefined;
  const parser = new XMLParser();
  do {
    const url = objectUrl(cfg, "");
    url.searchParams.set("list-type", "2");
    url.searchParams.set("prefix", prefix);
    if (token) url.searchParams.set("continuation-token", token);
    const res = await send(cfg, "GET", url, ca, {});
    if (!res.ok) throw await failure(res, "listing the bucket");
    const doc = parser.parse(await res.text()).ListBucketResult ?? {};
    const contents = doc.Contents === undefined ? [] : Array.isArray(doc.Contents) ? doc.Contents : [doc.Contents];
    for (const c of contents) keys.push(String(c.Key));
    token = doc.IsTruncated === true || doc.IsTruncated === "true" ? String(doc.NextContinuationToken) : undefined;
  } while (token);
  return keys;
}

export async function deleteObject(cfg: S3Config, key: string, ca?: string[]): Promise<void> {
  const res = await send(cfg, "DELETE", objectUrl(cfg, key), ca, {});
  if (!res.ok && res.status !== 404) throw await failure(res, `deleting ${key}`);
  await res.arrayBuffer().catch(() => undefined);
}
