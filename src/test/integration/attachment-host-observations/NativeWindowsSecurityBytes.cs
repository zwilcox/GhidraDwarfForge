// Test-only raw file-security observation. No metadata writes or privilege changes.
// GetFileSecurityW is audited against the pinned securitybaseapi.h recorded in
// src/test/native/windows-metadata-api.json and the C signature contract.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ForgeHostResearch {
    public static class NativeWindowsSecurityBytes {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileSecurityW(string path, uint fields,
            [Out] byte[] descriptor, uint length, out uint needed);

        public static byte[] Read(string path) {
            uint needed;
            bool first = GetFileSecurityW(path, 7, null, 0, out needed);
            int error = Marshal.GetLastWin32Error();
            if (first || error != 122) {
                throw new Win32Exception(error, "GetFileSecurityW size query did not report insufficient buffer");
            }
            if (needed < 20 || needed > 1024 * 1024) {
                throw new InvalidOperationException("File security descriptor exceeds bound");
            }
            var bytes = new byte[(int)needed];
            uint actual;
            if (!GetFileSecurityW(path, 7, bytes, needed, out actual)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileSecurityW read failed");
            }
            if (actual < 20 || actual > needed) {
                throw new InvalidOperationException("File security descriptor size changed");
            }
            if (actual != needed) Array.Resize(ref bytes, (int)actual);
            return bytes;
        }
    }
}
