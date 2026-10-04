import { describe, expect, it } from "vitest";
import { signRequest } from "./s3";

// AWS's own published SigV4 example for S3 ("GET Object" with a Range
// header, from the "Signature Calculations for the Authorization Header"
// page). Checked against the documented signature rather than against
// this implementation's own output, which would only prove it agrees with
// itself.
describe("signRequest", () => {
  it("reproduces AWS's documented example signature", () => {
    const headers = signRequest({
      method: "GET",
      url: new URL("https://examplebucket.s3.amazonaws.com/test.txt"),
      headers: { range: "bytes=0-9" },
      payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      accessKey: "AKIAIOSFODNN7EXAMPLE",
      secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      region: "us-east-1",
      now: new Date("2013-05-24T00:00:00Z"),
    });
    expect(headers.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
  });

  it("signs query parameters in sorted, encoded form", () => {
    const a = signRequest({
      method: "GET",
      url: new URL("https://s3.example/b?prefix=porttorch%2F&list-type=2"),
      headers: {},
      payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      accessKey: "k",
      secretKey: "s",
      region: "us-east-1",
      now: new Date("2026-01-01T00:00:00Z"),
    });
    const b = signRequest({
      method: "GET",
      url: new URL("https://s3.example/b?list-type=2&prefix=porttorch%2F"),
      headers: {},
      payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      accessKey: "k",
      secretKey: "s",
      region: "us-east-1",
      now: new Date("2026-01-01T00:00:00Z"),
    });
    // Parameter order in the URL must not change the signature.
    expect(a.authorization).toBe(b.authorization);
  });
});
