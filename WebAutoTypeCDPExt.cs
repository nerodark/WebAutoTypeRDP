using ChromeAutomation;
using HarmonyLib;
using KeePass;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePass.Util;
using KeePass.Util.Spr;
using KeePassLib;
using KeePassLib.Utility;
using Microsoft.CSharp.RuntimeBinder;
using Microsoft.WindowsAPICodePack.Shell;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Windows.Forms;

namespace WebAutoTypeCDP
{
    [HarmonyPatch]
    class AutoTypePatch
    {
        [HarmonyPrefix]
        [HarmonyPatch(typeof(AutoType), "PerformGlobal", new Type[] { typeof(List<PwDatabase>), typeof(ImageList), typeof(string) })]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0051:Remove unused private members", Justification = "Harmony Patch")]
        static bool PerformGlobalPrefix(ImageList ilIcons)
        {
            return !WebAutoTypeCDPExt.PerformAutoType(ilIcons);
        }
    }

    [ComImport, TypeLibType((short)0x1040), Guid("F935DC23-1CF0-11D0-ADB9-00C04FD58A0B")]
    interface IWshShortcut
    {
        [DispId(0)]
        string FullName { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0)] get; }
        [DispId(0x3e8)]
        string Arguments { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3e8)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3e8)] set; }
        [DispId(0x3e9)]
        string Description { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3e9)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3e9)] set; }
        [DispId(0x3ea)]
        string Hotkey { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3ea)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ea)] set; }
        [DispId(0x3eb)]
        string IconLocation { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3eb)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3eb)] set; }
        [DispId(0x3ec)]
        string RelativePath { [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ec)] set; }
        [DispId(0x3ed)]
        string TargetPath { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3ed)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ed)] set; }
        [DispId(0x3ee)]
        int WindowStyle { [DispId(0x3ee)] get; [param: In] [DispId(0x3ee)] set; }
        [DispId(0x3ef)]
        string WorkingDirectory { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3ef)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ef)] set; }
        [TypeLibFunc((short)0x40), DispId(0x7d0)]
        void Load([In, MarshalAs(UnmanagedType.BStr)] string PathLink);
        [DispId(0x7d1)]
        void Save();
    }

    public sealed class WebAutoTypeCDPExt : Plugin
    {
        private static readonly string WebAutoTypeOptionsConfigRoot = "WebAutoType.";
        private static readonly string UrlAutoTypeWindowTitlePrefix = "??:URL:";
        private static readonly string CheckPasswordBoxPlaceholder = "{PASSWORDBOX}";

        private static readonly object autoTypeLock = new object();

        private const string pluginName = "WebAutoTypeCDP";
        private const string setupMenuText = pluginName + " Setup";
        private const string setupCommandLineOption = "setup-webautotypecdp";

        private static readonly Type type = Type.GetTypeFromProgID("WScript.Shell");
        private static readonly object shell = Activator.CreateInstance(type);

        private static readonly List<AppBrowser> appBrowsers = new List<AppBrowser>();
        private static Dictionary<string, DevToolsPort> appBrowsersConfig = new Dictionary<string, DevToolsPort>()
        {
            { "Google Chrome", DevToolsPort.GoogleChrome },
            { "Microsoft Edge", DevToolsPort.MicrosoftEdge }
        };

        private enum DevToolsPort
        {
            GoogleChrome = 9222,
            MicrosoftEdge = 9223
        }

        private class AppBrowser
        {
            public string Name { get; set; }
            public string ExecutablePath { get; set; }
            public DevToolsPort DevToolsPort
            {
                get
                {
                    return appBrowsersConfig[Name];
                }
            }
        }

        private static IPluginHost Host { get; set; }

        private static bool WebAutoTypeMatchUrlField
        {
            get { return Host.CustomConfig.GetBool(WebAutoTypeOptionsConfigRoot + "MatchUrlField", true); }
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint ProcessId);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

        [DllImport("kernel32.dll")]
        private static extern bool QueryFullProcessImageName(IntPtr hprocess, int dwFlags, StringBuilder lpExeName, out int size);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hHandle);

        private static string GetActiveWindowTitle(IntPtr handle)
        {
            const int count = 256;
            var buffer = new StringBuilder(count);

            if (GetWindowText(handle, buffer, count) > 0)
            {
                return buffer.ToString();
            }

            return null;
        }

        private static int GetActiveProcessId(IntPtr handle)
        {
            uint pid;

            GetWindowThreadProcessId(handle, out pid);

            return Convert.ToInt32(pid);
        }

        private static string GetExecutablePath(int processId)
        {
            var buffer = new StringBuilder(1024);
            var process = OpenProcess(ProcessAccessFlags.QueryLimitedInformation, false, processId);

            if (process != IntPtr.Zero)
            {
                try
                {
                    int size = buffer.Capacity;

                    if (QueryFullProcessImageName(process, 0, buffer, out size))
                    {
                        return buffer.ToString();
                    }
                }
                finally
                {
                    CloseHandle(process);
                }
            }

            return null;
        }

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;

            Host = host;

            var setupCommandLine = Host.CommandLineArgs.Parameters.SingleOrDefault(p => p.Key == setupCommandLineOption);

            CacheInstalledAppBrowsers();

            if (!setupCommandLine.Equals(default(KeyValuePair<string, string>)))
            {
                Setup();
                
                Environment.Exit(0);
                return false;
            }

            var harmony = new Harmony(typeof(WebAutoTypeCDPExt).Name);
            harmony.PatchAll();

            SprEngine.FilterPlaceholderHints.Add(CheckPasswordBoxPlaceholder);

            return true;
        }

        private void CacheInstalledAppBrowsers()
        {
            var appsFolderId = new Guid("{1e87508d-89c2-42f0-8a7e-645a0f50ca58}");
            var appsFolder = KnownFolderHelper.FromKnownFolderId(appsFolderId);

            foreach (var app in appsFolder.Where(a => a.Properties.System.Link.TargetParsingPath.Value != null && a.Properties.System.Link.TargetParsingPath.Value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && appBrowsersConfig.ContainsKey(a.Name)))
            {
                appBrowsers.Add(new AppBrowser
                {
                    Name = app.Name,
                    ExecutablePath = app.Properties.System.Link.TargetParsingPath.Value
                });
            }
        }

        private void Setup()
        {
            TerminateBrowsers();

            foreach (var appBrowser in appBrowsers)
            {
                SetupBrowserShortcuts(appBrowser.Name, appBrowser.DevToolsPort);
            }
        }

        private static void TerminateBrowsers()
        {
            var appBrowserExecutables = appBrowsers.Select(a => System.IO.Path.GetFileNameWithoutExtension(a.ExecutablePath)).Distinct();

            foreach (var process in appBrowserExecutables.SelectMany(Process.GetProcessesByName))
            {
                process.Kill();
            }
        }

        private void SetupBrowserShortcuts(string linkFileName, DevToolsPort devToolsPort)
        {
            var startMenuLinkPath = string.Format(@"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\{0}.lnk", linkFileName);
            var taskBarLinkPath = string.Format(@"{0}\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\{1}.lnk", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), linkFileName);

            if (System.IO.File.Exists(startMenuLinkPath))
            {
                var link = (IWshShortcut)type.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { startMenuLinkPath });
                link.Arguments = Regex.Replace(link.Arguments, @"\s*[^\s]*\-\-remote\-debugging\-port=[^\s]*\s*", " ");
                link.Arguments = string.Format("--remote-debugging-port=\"{0:D}\" {1}", devToolsPort, link.Arguments.Trim());
                link.Save();
            }

            if (System.IO.File.Exists(taskBarLinkPath))
            {
                var link = (IWshShortcut)type.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { taskBarLinkPath });
                link.Arguments = Regex.Replace(link.Arguments, @"\s*[^\s]*\-\-remote\-debugging\-port=[^\s]*\s*", " ");
                link.Arguments = string.Format("--remote-debugging-port=\"{0:D}\" {1}", devToolsPort, link.Arguments.Trim());
                link.Save();
            }
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
        {
            if (t != PluginMenuType.Main) return null;

            var tsmi = new ToolStripMenuItem();
            tsmi.Text = setupMenuText;
            tsmi.Click += this.OnSetupClicked;

            return tsmi;
        }

        private void OnSetupClicked(object sender, EventArgs e)
        {
            var result = MessageBox.Show("Setup requires all browser instances to be closed.\n\nThe plugin will enable a remote debugging port on all supported browsers through their shotcuts.\n\nIf you continue, any browser instance still running will be terminated.", setupMenuText, MessageBoxButtons.OKCancel, MessageBoxIcon.Warning);

            if (result == DialogResult.OK)
            {
                var limitToSingleInstance = Program.Config.Integration.LimitToSingleInstance;

                if (limitToSingleInstance)
                {
                    Program.Config.Integration.LimitToSingleInstance = false;
                    Program.MainForm.SaveConfig();
                }

                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = Assembly.GetEntryAssembly().CodeBase,
                    Arguments = string.Format("-{0}", setupCommandLineOption),
                    Verb = "runas"
                });
                process.WaitForExit();

                if (limitToSingleInstance)
                {
                    Program.Config.Integration.LimitToSingleInstance = limitToSingleInstance;
                    Program.MainForm.SaveConfig();
                }

                MessageBox.Show("Setup finished successfully.", setupMenuText, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        public static bool PerformAutoType(ImageList icons)
        {
            lock (autoTypeLock)
            {
                try
                {
                    var windowHandle = GetForegroundWindow();

                    if (windowHandle == IntPtr.Zero) return false;

                    var activeProcessFileName = GetActiveProcessId(windowHandle);
                    var executablePath = GetExecutablePath(activeProcessFileName);

                    if (executablePath == null) return false;

                    var appBrowser = appBrowsers.SingleOrDefault(a => a.ExecutablePath == executablePath);

                    if (appBrowser == null)
                    {
                        MessageBox.Show($"The active browser is not supported:\n\n{executablePath}", pluginName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return false;
                    }

                    var chrome = new Chrome(string.Format("http://127.0.0.1:{0:D}", appBrowser.DevToolsPort));
                    IEnumerable<RemoteSessionsResponse> sessions = chrome.GetAvailableSessions();
                    sessions = sessions.Where(s => s.type == "page");

                    // Conditions order matters
                    if (   TryPerformAutoType(icons, chrome, sessions, IsBrowserUrlFocused, true)
                        || TryPerformAutoType(icons, chrome, sessions, IsBrowserUrlVisible, false))
                    {
                        // Return "true" to harmony patch to NOT execute KeePass's method.
                        return true;
                    }
                }
                catch (WebException)
                {
                    var result = MessageBox.Show("The active browser doesn't have a remote debugging port enabled.\n\nEither you didn't execute the plugin setup, the browser wasn't executed through a shortcut or another application/service started browser instances in the background that interfere with the plugin.\n\nYou can investigate based on the previous causes.\n\nDo you want to terminate any running browser instance?", pluginName, MessageBoxButtons.OKCancel, MessageBoxIcon.Error);

                    if (result == DialogResult.OK)
                    {
                        TerminateBrowsers();
                    }
                }
                catch (RuntimeBinderException)
                {
                    // The json response structure from CDP has changed. The code has to be updated.
                    MessageBox.Show("The active browser's DevTools protocol has changed.\n\nPlease contact the plugin's author.", pluginName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                catch (Exception)
                {
                    throw;
                }

                // Return "false" to harmony patch to execute KeePass's method normally.
                return false;
            }
        }

        private static bool TryPerformAutoType(ImageList icons, Chrome chrome, IEnumerable<RemoteSessionsResponse> sessions, Func<Chrome, bool> browserUrlValidator, bool canCheckPasswordBox)
        {
            var windowHandle = GetForegroundWindow();
            var activeWindowTitle = GetActiveWindowTitle(windowHandle);

            foreach (var session in sessions)
            {
                chrome.SetActiveSession(session.webSocketDebuggerUrl);

                if (activeWindowTitle.Contains(HttpUtility.HtmlDecode(session.title)) && browserUrlValidator(chrome))
                {
                    var entries = FindMatchingEntries(session.url);

                    if (entries.Count() > 1 || Program.Config.Integration.AutoTypeAlwaysShowSelDialog)
                    {
                        var ctxs = new List<AutoTypeCtx>();

                        foreach (var entry in entries)
                        {
                            ctxs.Add(new AutoTypeCtx(entry.GetAutoTypeSequence(), entry, Host.Database));
                        }

                        using (var autoTypeCtxForm = new AutoTypeCtxForm())
                        {
                            autoTypeCtxForm.InitEx(ctxs, icons);

                            if (autoTypeCtxForm.ShowDialog() == DialogResult.OK)
                            {
                                var entry = autoTypeCtxForm.SelectedCtx.Entry;

                                PerformAutoType(chrome, entry, canCheckPasswordBox);
                            }

                            UIUtil.DestroyForm(autoTypeCtxForm);
                        }
                    }
                    else if (entries.Count() == 1)
                    {
                        var entry = entries.Single();

                        PerformAutoType(chrome, entry, canCheckPasswordBox);
                    }

                    if (entries.Any())
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        // Inspired by the OnAutoTypeFilterCompilePre event from the CheckPasswordBox plugin.
        private static void PerformAutoType(Chrome chrome, PwEntry entry, bool canCheckPasswordBox)
        {
            var autoTypeSequence = entry.GetAutoTypeSequence();
            var index = autoTypeSequence.IndexOf(CheckPasswordBoxPlaceholder, StringComparison.InvariantCultureIgnoreCase);

            string sequence;
            string remainder = null;

            if (canCheckPasswordBox && index > -1)
            {
                if (!IsPasswordBoxFocused(chrome))
                {
                    sequence = autoTypeSequence.Substring(0, index);
                    remainder = autoTypeSequence.Substring(index + CheckPasswordBoxPlaceholder.Length);
                }
                else
                {
                    sequence = autoTypeSequence.Substring(index + CheckPasswordBoxPlaceholder.Length);
                    var nextIndex = sequence.IndexOf(CheckPasswordBoxPlaceholder, StringComparison.InvariantCultureIgnoreCase);
                    if (nextIndex > -1)
                    {
                        remainder = sequence.Substring(nextIndex);
                        sequence = sequence.Substring(0, nextIndex);
                    }
                }
            }
            else
            {
                sequence = autoTypeSequence.Replace(CheckPasswordBoxPlaceholder, string.Empty);
            }

            AutoType.PerformIntoCurrentWindow(entry, Host.Database, sequence);

            if (remainder != null)
            {
                // Trigger a second auto-type automatically after this one finishes, if it's in a password box now.
                if (IsPasswordBoxFocused(chrome))
                {
                    AutoType.PerformIntoCurrentWindow(entry, Host.Database, remainder);
                }
            }
        }

        private static bool IsBrowserUrlFocused(Chrome chrome)
        {
            var json = chrome.Eval("document.hasFocus()");

            dynamic result = JsonConvert.DeserializeObject(json);
            result = result.result.result;

            if (result.type == "boolean")
            {
                return result.value == "true";
            }

            return false;
        }

        private static bool IsBrowserUrlVisible(Chrome chrome)
        {
            var json = chrome.Eval("document.visibilityState");

            dynamic result = JsonConvert.DeserializeObject(json);
            result = result.result.result;

            if (result.type == "string")
            {
                return result.value == "visible";
            }

            return false;
        }

        private static bool IsPasswordBoxFocused(Chrome chrome)
        {
            RegisterGetActiveElementFunction(chrome);

            var json = chrome.Eval("kpGetActiveElement().type");

            dynamic result = JsonConvert.DeserializeObject(json);
            result = result.result.result;

            if (result.type == "string")
            {
                return result.value == "password";
            }

            return false;
        }

        // Create a JavaScript function that returns the active element of a page, regardless of iframe window or shadow root.
        private static void RegisterGetActiveElementFunction(Chrome chrome)
        {
            chrome.Eval(@"
				function kpGetActiveElement(element = document.activeElement)
				{
					const contentDocument = element.contentDocument;
					const shadowRoot = element.shadowRoot;
					
					if (contentDocument && contentDocument.activeElement)
					{
						return kpGetActiveElement(contentDocument.activeElement);
					}

					if (shadowRoot && shadowRoot.activeElement)
					{
						return kpGetActiveElement(shadowRoot.activeElement);
					}
					
					return element;
				}
			");
        }

        // Inspired by the AutoType_SequenceQuery event from the WebAutoType plugin.
        private static IEnumerable<PwEntry> FindMatchingEntries(string url)
        {
            foreach (var entry in Host.Database.RootGroup.GetEntries(true))
            {
                if (entry.AutoType.Enabled)
                {
                    if (!Program.Config.Integration.AutoTypeExpiredCanMatch && entry.Expires && entry.ExpiryTime <= DateTime.UtcNow)
                    {
                        continue;
                    }

                    var matchFound = false;
                    foreach (var association in entry.AutoType.Associations)
                    {
                        string strUrlSpec = association.WindowName;
                        if (strUrlSpec == null)
                        {
                            continue;
                        }

                        strUrlSpec = strUrlSpec.Trim();

                        if (!strUrlSpec.StartsWith(UrlAutoTypeWindowTitlePrefix) || strUrlSpec.Length <= UrlAutoTypeWindowTitlePrefix.Length)
                        {
                            continue;
                        }

                        strUrlSpec = strUrlSpec.Substring(7);

                        if (strUrlSpec.Length > 0)
                        {
                            strUrlSpec = SprEngine.Compile(strUrlSpec, new SprContext(entry, Host.Database, SprCompileFlags.All));
                        }

                        bool bRegex = strUrlSpec.StartsWith(@"//") && strUrlSpec.EndsWith(@"//") && (strUrlSpec.Length > 4);
                        Regex objRegex = null;

                        if (bRegex)
                        {
                            try
                            {
                                objRegex = new Regex(strUrlSpec.Substring(2, strUrlSpec.Length - 4), RegexOptions.IgnoreCase);
                            }
                            catch (Exception)
                            {
                                bRegex = false;
                            }
                        }

                        if (bRegex)
                        {
                            if (objRegex.IsMatch(url))
                            {
                                matchFound = true;
                            }
                        }
                        else if (StrUtil.SimplePatternMatch(strUrlSpec, url, StrUtil.CaseIgnoreCmp))
                        {
                            matchFound = true;
                        }
                    }

                    if (WebAutoTypeMatchUrlField)
                    {
                        var urlFieldValue = entry.Strings.ReadSafe(PwDefs.UrlField);

                        var match = Regex.Match(urlFieldValue, @"^(?<scheme>\w+://)?(?<credentials>[^@/]+@)?(?<host>[^/]+?)(?<port>:\d+)?(?<path>/.*)?$");
                        if (match.Success)
                        {
                            // Convert URL into regex to match subdomains and sub-paths
                            var urlRegex = "^" + // Must be start of string
                                           GetValueOrDefault(match, "scheme", "https?://") + // Scheme or assume http/s
                                           Regex.Escape(match.Groups["credentials"].Value) + // Credentials if present, otherwise assert none
                                           @"(\w+\.)*" + // Allow any number of subdomains
                                           Regex.Escape(match.Groups["host"].Value) + // Host part
                                           GetValueOrDefault(match, "port", @"(:\d+)?") + // Exact port if specified, otherwise any or no port.
                                           GetValueOrDefault(match, "path", "(?:/|$)") + // Path part as specified, or ensure host ends with / or end of url
                                           ".*$"; // Allow anything at the end of the url

                            matchFound = Regex.IsMatch(url, urlRegex);
                        }
                        else
                        {
                            // Can't parse URL field value as URL, so fall back on plain equals
                            matchFound = urlFieldValue.Equals(url, StrUtil.CaseIgnoreCmp);
                        }
                    }

                    if (matchFound)
                    {
                        yield return entry;
                    }
                }
            }
        }

        // Inspired by the GetValueOrDefault function from the WebAutoType plugin.
        private static string GetValueOrDefault(Match match, string groupName, string defaultRegex)
        {
            var matchGroup = match.Groups[groupName];
            if (matchGroup.Success)
            {
                return Regex.Escape(matchGroup.Value);
            }

            return defaultRegex;
        }

        public override void Terminate()
        {
            if (Host == null) return;

            SprEngine.FilterPlaceholderHints.Remove(CheckPasswordBoxPlaceholder);
        }
    }
}
