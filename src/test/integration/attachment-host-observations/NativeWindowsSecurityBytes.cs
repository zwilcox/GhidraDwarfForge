// Test-only raw file-security observation. No metadata writes or privilege changes.
// APIs are audited against the pinned AclAPI.h/securitybaseapi.h recorded in
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

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint GetNamedSecurityInfoW(string path, int type, uint fields,
            IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsValidSecurityDescriptor(IntPtr descriptor);
        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static byte[] Read(string path) {
            IntPtr descriptor;
            uint error = GetNamedSecurityInfoW(path, 1, 7, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, out descriptor);
            if (error != 0) throw new Win32Exception((int)error, "GetNamedSecurityInfoW failed");
            if (descriptor == IntPtr.Zero) throw new InvalidOperationException("Missing security descriptor");
            try {
                if (!IsValidSecurityDescriptor(descriptor)) throw new InvalidOperationException("Invalid security descriptor");
                uint size = GetSecurityDescriptorLength(descriptor);
                if (size < 20 || size > 1024 * 1024) throw new InvalidOperationException("Security descriptor exceeds bound");
                var bytes = new byte[(int)size];
                Marshal.Copy(descriptor, bytes, 0, (int)size);
                return bytes;
            }
            finally {
                if (LocalFree(descriptor) != IntPtr.Zero) throw new InvalidOperationException("LocalFree failed");
            }
        }

        // Retain this legacy representation for diagnosis; it can clear
        // inherited-ACE flags and is not the byte-preservation oracle.
        public static byte[] ReadLegacy(string path) {
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
