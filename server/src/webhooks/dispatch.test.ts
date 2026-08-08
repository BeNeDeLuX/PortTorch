import { describe, expect, it } from "vitest";
import { buildTeamsAdaptiveCardBody } from "./dispatch";

// Pure formatting logic, no DB/network - the actual delivery (dispatchWebhook
// itself) isn't unit-tested anywhere in this codebase, consistent with the
// rest of webhooks/ (see tests/integration/webhooks.integration.test.ts's
// CRUD/validation-only scope) - this just verifies the Teams request body
// is shaped the way Microsoft's Adaptive Card + Workflows webhook docs
// require, since a malformed envelope silently fails to render in Teams.
describe("buildTeamsAdaptiveCardBody", () => {
  it("wraps the message in a bot-framework message activity with an Adaptive Card attachment", () => {
    const parsed = JSON.parse(buildTeamsAdaptiveCardBody("Test title", "Test message"));

    expect(parsed.type).toBe("message");
    expect(parsed.attachments).toHaveLength(1);
    expect(parsed.attachments[0].contentType).toBe("application/vnd.microsoft.card.adaptive");

    const card = parsed.attachments[0].content;
    expect(card.type).toBe("AdaptiveCard");
    expect(card.$schema).toBe("http://adaptivecards.io/schemas/adaptive-card.json");
    expect(card.body).toEqual([
      { type: "TextBlock", text: "Test title", weight: "bolder", size: "medium", wrap: true },
      { type: "TextBlock", text: "Test message", wrap: true },
    ]);
  });

  it("produces valid JSON even when the title/message contain characters that need escaping", () => {
    const parsed = JSON.parse(buildTeamsAdaptiveCardBody('Title "with quotes"', "Line one\nLine two"));
    expect(parsed.attachments[0].content.body[0].text).toBe('Title "with quotes"');
    expect(parsed.attachments[0].content.body[1].text).toBe("Line one\nLine two");
  });
});
