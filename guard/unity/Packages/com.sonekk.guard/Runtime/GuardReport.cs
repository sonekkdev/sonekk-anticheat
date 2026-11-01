using System;
using System.Text;
using UnityEngine;

namespace Sonekk.Guard
{
    [Serializable]
    public class GuardFinding
    {
        public string id;
        public string sev;
        public int w;
        public string d;
    }

    [Serializable]
    public class GuardReport
    {
        public int v;
        public string sdk;
        public int score;
        public string verdict;
        public GuardFinding[] findings;

        public bool IsBlock => verdict == "block";

        public static GuardReport Parse(string json)
        {
            if (string.IsNullOrEmpty(json)) return null;
            try
            {
                return JsonUtility.FromJson<GuardReport>(json);
            }
            catch (Exception)
            {
                return null;
            }
        }
    }

    [CreateAssetMenu(menuName = "Sonekk Guard/Settings", fileName = "SonekkGuardSettings")]
    public class GuardSettings : ScriptableObject
    {
        [Tooltip("Base URL of your report endpoint, for example https://ac.mygame.com")]
        public string endpoint = "";

        [Tooltip("Shared secret used to sign reports. Not a security boundary, it only stops casual spam.")]
        public string apiKey = "";

        [Tooltip("Seconds between reports. Keep it slow, one or two per session is enough.")]
        [Range(0, 3600)]
        public int reportIntervalSeconds = 300;

        [Tooltip("Collect and log a report on start, without posting it.")]
        public bool reportOnStart = true;

        [Tooltip("Request a hardware Keystore attestation and send it with every report. Requires a server with trusted roots.")]
        public bool requestAttestation = false;

        [Tooltip("SHA-256 of libsonekk_guard.so from a known good build. Leave empty to skip the check.")]
        public string expectedLibraryHash = "";
    }
}
