using System;
using System.Collections;
using System.Text;
using UnityEngine;
using UnityEngine.Networking;

namespace Sonekk.Guard
{
    /// <summary>
    /// Drop this on a single GameObject in your first scene. It asks the server for a single
    /// use challenge, collects a report off the main thread, signs it, and posts it.
    /// </summary>
    public class GuardRunner : MonoBehaviour
    {
        [SerializeField] private GuardSettings settings;
        [SerializeField] private string pinnedSignatureSha256 = "";
        [SerializeField] private string playerId = "";

        [Serializable]
        private class ChallengeResponse
        {
            public string nonce;
        }

        private void Start()
        {
            if (settings == null)
            {
                Debug.LogWarning("[Sonekk Guard] No settings asset assigned, guard is idle.");
                return;
            }

            if (!SonekkGuard.IsAvailable)
            {
                Debug.Log("[Sonekk Guard] Native library missing, guard is inactive on this platform.");
                return;
            }

            if (settings.reportOnStart) StartCoroutine(CollectAndSend());

            if (settings.reportIntervalSeconds > 0)
            {
                InvokeRepeating(nameof(StartReport), settings.reportIntervalSeconds, settings.reportIntervalSeconds);
            }
        }

        private void StartReport()
        {
            StartCoroutine(CollectAndSend());
        }

        private IEnumerator CollectAndSend()
        {
            var endpoint = settings.endpoint == null ? "" : settings.endpoint.TrimEnd('/');
            var nonce = "";

            if (!string.IsNullOrEmpty(endpoint))
            {
                using var challengeRequest = new UnityWebRequest(endpoint + "/v1/challenge", "POST");
                challengeRequest.downloadHandler = new DownloadHandlerBuffer();
                challengeRequest.timeout = 10;
                yield return challengeRequest.SendWebRequest();

                if (challengeRequest.result == UnityWebRequest.Result.Success)
                {
                    var parsed = JsonUtility.FromJson<ChallengeResponse>(challengeRequest.downloadHandler.text);
                    if (parsed != null && !string.IsNullOrEmpty(parsed.nonce)) nonce = parsed.nonce;
                }
                else
                {
                    Debug.LogWarning("[Sonekk Guard] Could not get a challenge: " + challengeRequest.error);
                }
            }

            var debuggable = SonekkGuard.IsDebuggable();
            var signatureOk = SonekkGuard.SignatureMatches(pinnedSignatureSha256);
            var expectedHash = settings.expectedLibraryHash;

            var task = System.Threading.Tasks.Task.Run(
                () => SonekkGuard.Collect(expectedHash, signatureOk, debuggable));
            while (!task.IsCompleted) yield return null;

            if (task.Exception != null)
            {
                Debug.LogWarning("[Sonekk Guard] Collection failed: " + task.Exception.Message);
                yield break;
            }

            var report = task.Result;
            if (string.IsNullOrEmpty(report)) yield break;

            if (string.IsNullOrEmpty(endpoint))
            {
                Debug.Log("[Sonekk Guard] " + report);
                yield break;
            }

            var attestation = settings.requestAttestation && nonce.Length > 0
                ? SonekkGuard.RequestAttestation(nonce)
                : null;

            var payload = BuildPayload(report, nonce, playerId, attestation);

            using var request = new UnityWebRequest(endpoint + "/v1/report", "POST");
            request.uploadHandler = new UploadHandlerRaw(Encoding.UTF8.GetBytes(payload));
            request.downloadHandler = new DownloadHandlerBuffer();
            request.SetRequestHeader("Content-Type", "application/json");
            request.SetRequestHeader("X-Sonekk-Signature", SonekkGuard.Sign(payload, settings.apiKey));
            request.timeout = 15;

            yield return request.SendWebRequest();

            if (request.result != UnityWebRequest.Result.Success)
            {
                Debug.LogWarning("[Sonekk Guard] Report rejected: " + request.error);
                yield break;
            }

            var response = GuardReport.Parse(request.downloadHandler.text);
            if (response != null && response.verdict == "block")
            {
                // Your game decides what a block means. Never ban from the client.
                Debug.LogWarning("[Sonekk Guard] Server returned block for this session.");
            }
        }

        private static string BuildPayload(string report, string nonce, string player, string attestation)
        {
            var body = report.EndsWith("}") ? report.Substring(0, report.Length - 1) : report;
            var builder = new StringBuilder(body);

            if (!string.IsNullOrEmpty(nonce))
            {
                builder.Append(",\"nonce\":\"").Append(JsonSafe(nonce)).Append('"');
            }

            if (!string.IsNullOrEmpty(player))
            {
                builder.Append(",\"player\":\"").Append(JsonSafe(player)).Append('"');
            }

            if (!string.IsNullOrEmpty(attestation))
            {
                builder.Append(",\"attestation\":").Append(attestation);
            }

            builder.Append('}');
            return builder.ToString();
        }

        private static string JsonSafe(string value)
        {
            return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }
}
