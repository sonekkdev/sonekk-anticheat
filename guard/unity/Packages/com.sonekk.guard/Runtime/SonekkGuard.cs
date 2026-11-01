using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;

namespace Sonekk.Guard
{
    /// <summary>
    /// Native detection bridge. Only Android builds ship libsonekk_guard.so, so every
    /// other platform returns null and the game keeps working untouched.
    /// </summary>
    public static class SonekkGuard
    {
#if UNITY_ANDROID && !UNITY_EDITOR
        [DllImport("sonekk_guard")]
        private static extern IntPtr sonekk_guard_analyze(string configJson);

        [DllImport("sonekk_guard")]
        private static extern void sonekk_guard_free(IntPtr pointer);

        [DllImport("sonekk_guard")]
        private static extern IntPtr sonekk_guard_version;
#endif

        public static bool IsAvailable
        {
            get
            {
#if UNITY_ANDROID && !UNITY_EDITOR
                return true;
#else
                return false;
#endif
            }
        }

        /// <summary>Runs every check and returns the raw report JSON, or null when unsupported.</summary>
        public static string Collect(string expectedLibraryHash = "", bool signatureOk = true, bool debuggable = false)
        {
#if UNITY_ANDROID && !UNITY_EDITOR
            var config = "{\"expectedSelfHash\":\"" + Escape(expectedLibraryHash) + "\",\"signatureOk\":"
                         + (signatureOk ? "true" : "false")
                         + ",\"debuggable\":" + (debuggable ? "true" : "false") + "}";
            var pointer = sonekk_guard_analyze(config);
            if (pointer == IntPtr.Zero) return null;
            try
            {
                return Marshal.PtrToStringAnsi(pointer);
            }
            finally
            {
                sonekk_guard_free(pointer);
            }
#else
            return null;
#endif
        }

        public static string Version
        {
            get
            {
#if UNITY_ANDROID && !UNITY_EDITOR
                var pointer = sonekk_guard_version;
                return pointer == IntPtr.Zero ? "0.0.0" : Marshal.PtrToStringAnsi(pointer);
#else
                return "unavailable";
#endif
            }
        }


        /// <summary>
        /// Asks the TEE for a certified key bound to the challenge and signs it.
        /// Returns {"chain":[...],"signature":"..."} or null when unsupported.
        /// This is the only proof a rooted device cannot fabricate, because the key
        /// never leaves the secure element.
        /// </summary>
        public static string RequestAttestation(string challenge)
        {
#if UNITY_ANDROID && !UNITY_EDITOR
            if (string.IsNullOrEmpty(challenge)) return null;

            const string alias = "sonekk_guard_attestation";
            const int purposeSign = 6;

            try
            {
                using var keyStoreClass = new AndroidJavaClass("java.security.KeyStore");
                using var keyStore = keyStoreClass.CallStatic<AndroidJavaObject>("getInstance", "AndroidKeyStore");
                keyStore.Call("load", new object[] { null });

                using var generatorClass = new AndroidJavaClass("java.security.KeyPairGenerator");
                using var generator = generatorClass.CallStatic<AndroidJavaObject>("getInstance", "EC", "AndroidKeyStore");

                using var properties = new AndroidJavaClass("android.security.keystore.KeyProperties");
                var digest = properties.GetStatic<string>("DIGEST_SHA256");

                using var builder = new AndroidJavaObject("android.security.keystore.KeyGenParameterSpec$Builder", alias, purposeSign);
                builder.Call<AndroidJavaObject>("setDigests", digest);
                builder.Call<AndroidJavaObject>("setAttestationChallenge", Encoding.UTF8.GetBytes(challenge));

                using var spec = builder.Call<AndroidJavaObject>("build");
                generator.Call("initialize", spec);
                generator.Call<AndroidJavaObject>("generateKeyPair");

                using var chain = keyStore.Call<AndroidJavaObject>("getCertificateChain", alias);
                var count = chain.Call<int>("size");
                if (count <= 0) return null;

                var parts = new StringBuilder();
                for (var i = 0; i < count; i += 1)
                {
                    using var certificate = chain.Call<AndroidJavaObject>("get", i);
                    var encoded = certificate.Call<byte[]>("getEncoded");
                    if (encoded == null) continue;
                    if (parts.Length > 0) parts.Append(',');
                    parts.Append('"').Append(Convert.ToBase64String(encoded)).Append('"');
                }

                using var privateKey = keyStore.Call<AndroidJavaObject>("getKey", alias, null);
                using var signatureClass = new AndroidJavaClass("java.security.Signature");
                using var signature = signatureClass.CallStatic<AndroidJavaObject>("getInstance", "SHA256withECDSA");
                signature.Call("initSign", privateKey);
                signature.Call("update", Encoding.UTF8.GetBytes(challenge));
                var signed = signature.Call<byte[]>("sign");

                return "{\"chain\":[" + parts + "],\"signature\":\"" + Convert.ToBase64String(signed) + "\"}";
            }
            catch (Exception exception)
            {
                Debug.LogWarning("[Sonekk Guard] Attestation unavailable: " + exception.Message);
                return null;
            }
#else
            return null;
#endif
        }

        /// <summary>True when the APK was built with android:debuggable, a strong signal it is a repack.</summary>
        public static bool IsDebuggable()
        {
#if UNITY_ANDROID && !UNITY_EDITOR
            try
            {
                using var player = new AndroidJavaClass("com.unity3d.player.UnityPlayer");
                using var activity = player.GetStatic<AndroidJavaObject>("currentActivity");
                using var info = activity.Call<AndroidJavaObject>("getApplicationInfo");
                var flags = info.Get<int>("flags");
                return (flags & 0x2) != 0;
            }
            catch (Exception)
            {
                return false;
            }
#else
            return false;
#endif
        }

        /// <summary>Compares the installed APK signature with the one pinned at build time.</summary>
        public static bool SignatureMatches(string expectedSha256)
        {
            if (string.IsNullOrEmpty(expectedSha256)) return true;
#if UNITY_ANDROID && !UNITY_EDITOR
            try
            {
                using var player = new AndroidJavaClass("com.unity3d.player.UnityPlayer");
                using var activity = player.GetStatic<AndroidJavaObject>("currentActivity");
                using var packageManager = activity.Call<AndroidJavaObject>("getPackageManager");
                var packageName = activity.Call<string>("getPackageName");
                using var info = packageManager.Call<AndroidJavaObject>("getPackageInfo", packageName, 0x40);
                using var signatures = info.Get<AndroidJavaObject>("signatures");
                var signature = signatures.Get<AndroidJavaObject>(0).Call<byte[]>("toByteArray");

                using var sha = SHA256.Create();
                var digest = sha.ComputeHash(signature);
                var builder = new StringBuilder(digest.Length * 2);
                foreach (var b in digest) builder.Append(b.ToString("x2"));
                return string.Equals(builder.ToString(), expectedSha256, StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception)
            {
                // Unreadable package info is treated as untrusted, not as a crash.
                return false;
            }
#else
            return true;
#endif
        }

        public static string Sign(string payload, string secret)
        {
            if (string.IsNullOrEmpty(secret)) return "";
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
            var builder = new StringBuilder(hash.Length * 2);
            foreach (var b in hash) builder.Append(b.ToString("x2"));
            return builder.ToString();
        }

        private static string Escape(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }
}
