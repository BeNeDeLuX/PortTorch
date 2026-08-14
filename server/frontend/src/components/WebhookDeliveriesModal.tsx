import { useEffect, useState } from "react";
import { api, UserPreferences, WebhookDelivery } from "../api";
import Modal from "./Modal";
import { formatDateTime } from "../lib/formatDate";

// The only place an admin could previously tell whether a webhook is
// actually working was the raw stdout logs (webhook.delivery_failed) -
// this is the last MAX_DELIVERIES_PER_WEBHOOK (dispatch.ts) attempts for
// one webhook, fetched once on open rather than polled, since past
// deliveries don't change.
export default function WebhookDeliveriesModal({
  webhookId,
  webhookName,
  preferences,
  onClose,
}: {
  webhookId: string;
  webhookName: string;
  preferences: UserPreferences;
  onClose: () => void;
}) {
  const [deliveries, setDeliveries] = useState<WebhookDelivery[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .webhookDeliveries(webhookId)
      .then(setDeliveries)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load delivery history"));
  }, [webhookId]);

  return (
    <Modal title={`Delivery history: ${webhookName}`} onClose={onClose}>
      {error ? (
        <p className="error">{error}</p>
      ) : deliveries === null ? (
        <p>Loading...</p>
      ) : deliveries.length === 0 ? (
        <p className="empty">No deliveries recorded yet - nothing has fired for this webhook.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Event</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {deliveries.map((d) => (
              <tr key={d.id}>
                <td>{formatDateTime(d.created_at, preferences)}</td>
                <td>{d.event}</td>
                <td>
                  {d.success ? (
                    <span className="expiry-label expiry-ok">ok{d.status_code ? ` (${d.status_code})` : ""}</span>
                  ) : (
                    <span className="expiry-label expiry-expired" title={d.error ?? undefined}>
                      failed{d.status_code ? ` (${d.status_code})` : ""}
                      {d.error ? `: ${d.error}` : ""}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  );
}
