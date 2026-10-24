// Ignored research fixture operations only. No production API or transaction.
// Exact SDK mappings: api-provenance.json. Native execution requires root review.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ForgeHostResearch {
    public static class WindowsReplacementPrimitives {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CopyFileW(string source, string destination,
            [MarshalAs(UnmanagedType.Bool)] bool failIfExists);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReplaceFileW(string target, string candidate, string backup,
            uint flags, IntPtr exclude, IntPtr reserved);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint sharing,
            IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FlushFileBuffers(SafeFileHandle handle);

        public static Dictionary<string, object> CopyNew(string source, string destination) {
            bool ok = CopyFileW(source, destination, true);
            int error = ok ? 0 : Marshal.GetLastWin32Error();
            return new Dictionary<string, object> {
                ["api"] = "CopyFileW", ["source"] = source, ["destination"] = destination,
                ["failIfExists"] = true, ["success"] = ok, ["win32Error"] = error
            };
        }

        public static Dictionary<string, object> Replace(string target, string candidate) {
            bool ok = ReplaceFileW(target, candidate, null, 0, IntPtr.Zero, IntPtr.Zero);
            int error = ok ? 0 : Marshal.GetLastWin32Error();
            return new Dictionary<string, object> {
                ["api"] = "ReplaceFileW", ["target"] = target, ["candidate"] = candidate,
                ["nativeBackup"] = null, ["flags"] = 0, ["success"] = ok, ["win32Error"] = error,
                ["scope"] = "Observed primitive outcome; failure may include partial namespace/metadata changes"
            };
        }

        public static Dictionary<string, object> Flush(string path, bool directory) {
            uint flags = directory ? 0x02000000U : 0U;
            var result = new Dictionary<string, object> {
                ["api"] = "FlushFileBuffers", ["path"] = path, ["directory"] = directory,
                ["desiredAccess"] = 0x40000000U, ["shareMode"] = 7U,
                ["creationDisposition"] = 3U, ["flags"] = flags,
                ["scope"] = "Return observation only; no namespace/power-loss durability conclusion"
            };
            using (SafeFileHandle handle = CreateFileW(path, 0x40000000U, 7, IntPtr.Zero, 3, flags, IntPtr.Zero)) {
                int openError = handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
                result["openError"] = openError;
                if (handle.IsInvalid) {
                    result["stage"] = "OPEN";
                    result["success"] = false;
                    return result;
                }
                bool ok = FlushFileBuffers(handle);
                int error = ok ? 0 : Marshal.GetLastWin32Error();
                result["stage"] = "FLUSH";
                result["success"] = ok;
                result["win32Error"] = error;
                return result;
            }
        }
    }
}
