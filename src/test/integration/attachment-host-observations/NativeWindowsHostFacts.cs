// Test-only, read-only observations. No production native ABI or publication API.
// Audited against microsoft/win32metadata commit 2f767671802301cf043c717d66bf004ed7863487:
// fileapi.h, WinBase.h, minwinbase.h, winnt.h. See windows-api-contract.json.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ForgeHostResearch {
    public static class NativeWindowsHostFacts {
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInformation {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME AccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME WriteTime;
            public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct AttributeTag {
            public uint Attributes, Tag;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct FileId {
            public ulong VolumeSerial;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Identifier;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StreamData {
            public long Size;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string Name;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
            IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation value);
        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTag(SafeFileHandle handle, int kind, out AttributeTag value, uint size);
        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetId(SafeFileHandle handle, int kind, out FileId value, uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr FindFirstStreamW(string path, int level, out StreamData data, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindNextStreamW(IntPtr handle, out StreamData data);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindClose(IntPtr handle);

        public static Dictionary<string, object> Layouts() {
            var result = new Dictionary<string, object>();
            result["pointerBytes"] = IntPtr.Size;
            result["byHandleBytes"] = Marshal.SizeOf(typeof(FileInformation));
            result["tagBytes"] = Marshal.SizeOf(typeof(AttributeTag));
            result["fileIdBytes"] = Marshal.SizeOf(typeof(FileId));
            result["streamDataBytes"] = Marshal.SizeOf(typeof(StreamData));
            if (IntPtr.Size != 8 || (int)result["byHandleBytes"] != 52 ||
                    (int)result["tagBytes"] != 8 || (int)result["fileIdBytes"] != 24 ||
                    (int)result["streamDataBytes"] != 600) {
                throw new InvalidOperationException("unproved native structure layout");
            }
            return result;
        }

        // Access is restricted to metadata-only or GENERIC_READ. OPEN_EXISTING only.
        public static Dictionary<string, object> Observe(string path, bool follow, bool readAccess) {
            Layouts();
            uint access = readAccess ? 0x80000000u : 0u;
            uint flags = 0x02000000u | (follow ? 0u : 0x00200000u);
            var result = new Dictionary<string, object> {
                {"path", path}, {"followLeaf", follow}, {"desiredAccess", access},
                {"shareMode", 7u}, {"creationDisposition", 3u}, {"flags", flags},
                {"identityLifetime", "Opened-handle observation only; no enduring identity or lock claim"}
            };
            using (SafeFileHandle handle = CreateFileW(path, access, 7, IntPtr.Zero, 3, flags, IntPtr.Zero)) {
                int error = handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
                result["openWin32Error"] = error;
                if (handle.IsInvalid) { result["status"] = "UNAVAILABLE"; return result; }
                FileInformation info;
                if (!GetFileInformationByHandle(handle, out info)) {
                    result["informationWin32Error"] = Marshal.GetLastWin32Error();
                    result["status"] = "UNAVAILABLE";
                    return result;
                }
                result["status"] = "OBSERVED";
                result["attributes"] = info.Attributes;
                result["links"] = info.Links;
                result["size"] = ((ulong)info.SizeHigh << 32) | info.SizeLow;
                result["legacyVolume"] = info.VolumeSerial.ToString("x8");
                result["legacyFileId"] = info.IndexHigh.ToString("x8") + info.IndexLow.ToString("x8");
                result["legacyIdentityScope"] = "64-bit file ID is not guaranteed unique on ReFS; no fallback acceptance";
                result["creationTime"] = FileTime(info.CreationTime);
                result["accessTime"] = FileTime(info.AccessTime);
                result["writeTime"] = FileTime(info.WriteTime);
                AttributeTag tag;
                if (GetTag(handle, 9, out tag, (uint)Marshal.SizeOf(typeof(AttributeTag)))) {
                    result["attributeTagStatus"] = "OBSERVED";
                    result["reparseTag"] = tag.Tag;
                    result["tagAttributes"] = tag.Attributes;
                } else {
                    result["attributeTagStatus"] = "UNAVAILABLE";
                    result["attributeTagWin32Error"] = Marshal.GetLastWin32Error();
                }
                using (SafeFileHandle second = CreateFileW(path, access, 7, IntPtr.Zero, 3, flags, IntPtr.Zero)) {
                    int secondError = second.IsInvalid ? Marshal.GetLastWin32Error() : 0;
                    var simultaneous = new Dictionary<string, object> {{"openWin32Error", secondError}};
                    result["secondSimultaneousHandle"] = simultaneous;
                    FileInformation secondInfo;
                    if (!second.IsInvalid && GetFileInformationByHandle(second, out secondInfo)) {
                        simultaneous["status"] = "OBSERVED";
                        simultaneous["legacyVolume"] = secondInfo.VolumeSerial.ToString("x8");
                        simultaneous["legacyFileId"] = secondInfo.IndexHigh.ToString("x8") + secondInfo.IndexLow.ToString("x8");
                        simultaneous["links"] = secondInfo.Links;
                        FileId secondId;
                        if (GetId(second, 18, out secondId, (uint)Marshal.SizeOf(typeof(FileId)))) {
                            simultaneous["volume128"] = secondId.VolumeSerial.ToString("x16");
                            simultaneous["fileId128"] = BitConverter.ToString(secondId.Identifier).Replace("-", "").ToLowerInvariant();
                        } else { simultaneous["fileIdWin32Error"] = Marshal.GetLastWin32Error(); }
                    } else {
                        simultaneous["status"] = "UNAVAILABLE";
                        if (!second.IsInvalid) simultaneous["informationWin32Error"] = Marshal.GetLastWin32Error();
                    }
                }
                FileId id;
                if (GetId(handle, 18, out id, (uint)Marshal.SizeOf(typeof(FileId)))) {
                    result["fileIdStatus"] = "OBSERVED";
                    result["volume128"] = id.VolumeSerial.ToString("x16");
                    result["fileId128"] = BitConverter.ToString(id.Identifier).Replace("-", "").ToLowerInvariant();
                } else {
                    result["fileIdStatus"] = "UNAVAILABLE";
                    result["fileIdWin32Error"] = Marshal.GetLastWin32Error();
                }
            }
            return result;
        }

        private static ulong FileTime(System.Runtime.InteropServices.ComTypes.FILETIME value) {
            return ((ulong)(uint)value.dwHighDateTime << 32) | (uint)value.dwLowDateTime;
        }

        // Enumerates $DATA streams only. This does not enumerate EAs or security metadata.
        public static Dictionary<string, object> DataStreams(string path) {
            Layouts();
            var result = new Dictionary<string, object> {
                {"path", path}, {"scope", "Path-based followed $DATA streams only; not all native metadata"}
            };
            var rows = new List<Dictionary<string, object>>();
            result["streams"] = rows;
            StreamData data;
            IntPtr handle = FindFirstStreamW(path, 0, out data, 0);
            if (handle == new IntPtr(-1)) {
                result["status"] = "UNAVAILABLE";
                result["win32Error"] = Marshal.GetLastWin32Error();
                return result;
            }
            try {
                int totalNameUnits = 0;
                while (true) {
                    if (rows.Count >= 64 || data.Name == null || data.Size < 0 ||
                            (totalNameUnits += data.Name.Length) > 16384) {
                        result["status"] = "LIMIT_EXCEEDED";
                        return result;
                    }
                    rows.Add(new Dictionary<string, object> {{"name", data.Name}, {"size", data.Size}});
                    if (!FindNextStreamW(handle, out data)) {
                        int error = Marshal.GetLastWin32Error();
                        result["terminalWin32Error"] = error;
                        result["status"] = error == 38 ? "OBSERVED" : "UNAVAILABLE";
                        return result;
                    }
                }
            } finally {
                if (!FindClose(handle)) {
                    result["closeWin32Error"] = Marshal.GetLastWin32Error();
                    result["status"] = "UNAVAILABLE";
                }
            }
        }
    }
}
