using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using UnityEngine;
using UnityEngine.Networking;

namespace Sonekk.Guard
{
    /// <summary>
    /// Samples the player and posts batches to the movement validator. The server answers
    /// allow, kick or ban, your game decides how to disconnect. Nothing is enforced here.
    /// </summary>
    public class MovementReporter : MonoBehaviour
    {
        [SerializeField] private string endpoint = "";
        [SerializeField] private string playerId = "";
        [SerializeField] private float sampleHz = 10f;
        [SerializeField] private int batchSize = 50;
        [SerializeField] private float maxSpeed = 6.5f;

        public event Action<string> OnAction;

        private readonly List<Sample> samples = new List<Sample>();
        private Vector3 lastPosition;
        private float joinedAt;
        private bool dirty;

        [Serializable]
        private struct Sample
        {
            public long t;
            public float x, y, z;
            public bool grounded;
            public float groundY;
        }

        private void Start()
        {
            joinedAt = Time.realtimeSinceStartup;
            lastPosition = transform.position;
            StartCoroutine(SampleLoop());
        }

        /// <summary>Call when the game respawns or teleports the player on purpose.</summary>
        public void MarkLegalMove()
        {
            dirty = true;
        }

        private IEnumerator SampleLoop()
        {
            var interval = new WaitForSecondsRealtime(1f / Mathf.Max(1f, sampleHz));

            while (true)
            {
                yield return interval;

                var position = transform.position;
                var grounded = Physics.Raycast(position + Vector3.up * 0.1f, Vector3.down, out var hit, 1.5f);
                var sample = new Sample
                {
                    t = (long)((Time.realtimeSinceStartup - joinedAt) * 1000),
                    x = position.x,
                    y = position.y,
                    z = position.z,
                    grounded = grounded,
                    groundY = grounded ? hit.point.y : 0f
                };

                if (dirty)
                {
                    dirty = false;
                    lastPosition = position;
                    continue;
                }

                samples.Add(sample);
                lastPosition = position;

                if (samples.Count >= batchSize) yield return Send();
            }
        }

        private IEnumerator Send()
        {
            if (string.IsNullOrEmpty(endpoint) || samples.Count == 0) yield break;

            var body = BuildJson();
            samples.Clear();

            using var request = new UnityWebRequest(endpoint.TrimEnd('/') + "/v1/movement", "POST");
            request.uploadHandler = new UploadHandlerRaw(Encoding.UTF8.GetBytes(body));
            request.downloadHandler = new DownloadHandlerBuffer();
            request.SetRequestHeader("Content-Type", "application/json");
            request.timeout = 10;

            yield return request.SendWebRequest();
            if (request.result != UnityWebRequest.Result.Success) yield break;

            var response = request.downloadHandler.text;
            if (response.Contains("\"action\":\"kick\"")) OnAction?.Invoke("kick");
            else if (response.Contains("\"action\":\"ban\"")) OnAction?.Invoke("ban");
        }

        private string BuildJson()
        {
            var builder = new StringBuilder();
            builder.Append("{\"playerId\":\"").Append(Escape(playerId)).Append("\",");
            builder.Append("\"joinedAt\":").Append((long)(joinedAt * 1000)).Append(',');
            builder.Append("\"samples\":[");
            for (var i = 0; i < samples.Count; i += 1)
            {
                var sample = samples[i];
                if (i > 0) builder.Append(',');
                builder.Append("{\"t\":").Append(sample.t)
                    .Append(",\"x\":").Append(sample.x.ToString("0.###")).Append(",\"y\":").Append(sample.y.ToString("0.###"))
                    .Append(",\"z\":").Append(sample.z.ToString("0.###"))
                    .Append(",\"grounded\":").Append(sample.grounded ? "true" : "false")
                    .Append(",\"groundY\":").Append(sample.groundY.ToString("0.###")).Append('}');
            }
            builder.Append("]}");
            return builder.ToString();
        }

        private static string Escape(string value)
        {
            return (value ?? string.Empty).Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }
}
