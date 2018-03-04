using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace FingerPrintAuthenticator
{
    class RegistryHelper
    {
        public static bool KeyExists(string keyPath)
        {
            RegistryKey root = GetKeyRoot(keyPath);
            return root != null && root.OpenSubKey(keyPath.Substring(5)) != null;
        }

        public static bool ValueExists(string parentKey, string valueName)
        {
            RegistryKey root = GetKeyRoot(parentKey);
            if (root == null) throw new KeyNotFoundException($"The following registry key's root doesn't exist: {parentKey}");
            RegistryKey targetKey = root.OpenSubKey(parentKey);
            if (targetKey == null) throw new KeyNotFoundException($"The following registry key doesn't exist: {parentKey}");
            parentKey = parentKey.Substring(parentKey.IndexOf("\\") + 1);
            object value = targetKey.GetValue(valueName);
            return value == null;
        }

        public static string GetValue(string parentKey, string valueName)
        {
            RegistryKey root = GetKeyRoot(parentKey);
            if (root == null) throw new KeyNotFoundException($"The following registry key's root doesn't exist: {parentKey}");
            RegistryKey targetKey = root.OpenSubKey(parentKey);
            if (targetKey == null) throw new KeyNotFoundException($"The following registry key doesn't exist: {parentKey}");
            object value = targetKey.GetValue(valueName);
            if (value == null) throw new KeyNotFoundException($"The following registry key's value ({valueName}) doesn't exist: {parentKey}");
            return value.ToString();
        }

        public static void AddValue(string parentKey, string valueName, string value)
        {
            if (parentKey == null) throw new ArgumentNullException("Argument parentKey can't be null");
            RegistryKey root = GetKeyRoot(parentKey);
            if (root == null) throw new KeyNotFoundException($"The following registry key's root doesn't exist: {parentKey}");
            parentKey = parentKey.Substring(5);
            RegistryKey targetKey = root.OpenSubKey(parentKey);
            if (targetKey == null) throw new KeyNotFoundException($"The following registry key doesn't exist: {parentKey}");
            targetKey.SetValue(valueName, value);
        }

        public static RegistryKey AddKey(string parentKey, string keyName)
        {
            RegistryKey root = GetKeyRoot(parentKey);
            if (root == null) throw new KeyNotFoundException($"The following registry key's root doesn't exist: {parentKey}");
            RegistryKey targetKey = root.OpenSubKey(parentKey);
            if (targetKey == null) throw new KeyNotFoundException($"The following registry key doesn't exist: {parentKey}");
            return targetKey.CreateSubKey(keyName);
        }

        private static RegistryKey GetKeyRoot(string path)
        {
            string root = path.Substring(0, 4);

            switch (root)
            {
                case "HKCR":
                    return Registry.ClassesRoot;
                case "HKCU":
                    return Registry.CurrentUser;
                case "HKLM":
                    return Registry.LocalMachine;
                case "HKU":
                    return Registry.Users;
                case "HKCC":
                    return Registry.CurrentConfig;
                default:
                    return null;
            }
        }
    }
}
