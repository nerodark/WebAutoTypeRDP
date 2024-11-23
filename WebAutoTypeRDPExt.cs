using HarmonyLib;
using KeePass;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePass.Util;
using KeePass.Util.Spr;
using KeePassLib;
using KeePassLib.Utility;
using Microsoft.WindowsAPICodePack.Shell;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.WebSockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Forms;

namespace WebAutoTypeRDP
{
    [HarmonyPatch]
    class AutoTypePatch
    {
        [HarmonyPrefix]
        [HarmonyPatch(typeof(AutoType), "PerformGlobal", new Type[] { typeof(List<PwDatabase>), typeof(ImageList), typeof(string) })]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0051:Remove unused private members", Justification = "Harmony Patch")]
        static bool PerformGlobalPrefix(ImageList ilIcons)
        {
            return !Task.Run(() => WebAutoTypeRDPExt.PerformAutoType(ilIcons)).Result;
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

    public sealed class WebAutoTypeRDPExt : Plugin
    {
        private static readonly string WebAutoTypeOptionsConfigRoot = "WebAutoType.";
        private static readonly string UrlAutoTypeWindowTitlePrefix = "??:URL:";
        private static readonly string CheckPasswordBoxPlaceholder = "{PASSWORDBOX}";

        private static readonly SemaphoreSlim autoTypeSemaphore = new SemaphoreSlim(1, 1);

        private const string pluginName = "WebAutoTypeRDP";
        private const string setupMenuText = pluginName + " Setup";
        private const string setupCommandLineOption = "setup-WebAutoTypeRDP";

        private static readonly Type type = Type.GetTypeFromProgID("WScript.Shell");
        private static readonly object shell = Activator.CreateInstance(type);

        private static readonly List<AppBrowser> appBrowsers = new List<AppBrowser>();
        // Browsers are found and setup by their link file name.
        private static Dictionary<string, AppBrowserConfig> appBrowsersConfig = new Dictionary<string, AppBrowserConfig>()
        {
            {
                "Google Chrome",
                new AppBrowserConfig {
                    Name = "Google Chrome",
                    LinkFileName = "Google Chrome",
                    RemoteDebuggingPort = RemoteDebuggingPort.GoogleChrome
                }
            },
            {
                "Microsoft Edge",
                new AppBrowserConfig {
                    Name = "Microsoft Edge",
                    LinkFileName = "Microsoft Edge",
                    RemoteDebuggingPort = RemoteDebuggingPort.MicrosoftEdge
                }
            },
            {
                "Mozilla Firefox",
                new AppBrowserConfig {
                    Name = "Mozilla Firefox",
                    LinkFileName = "Firefox",
                    RemoteDebuggingPort = RemoteDebuggingPort.MozillaFirefox
                }
            }
        };

        private enum RemoteDebuggingPort
        {
            GoogleChrome = 9222,
            MicrosoftEdge = 9223,
            MozillaFirefox = 9224
        }

        private class AppBrowser
        {
            public string Name { get; set; }
            public string LinkFileName { get; set; }
            public string ExecutablePath { get; set; }
            public RemoteDebuggingPort RemoteDebuggingPort
            {
                get
                {
                    return appBrowsersConfig[Name].RemoteDebuggingPort;
                }
            }
        }

        private class AppBrowserConfig
        {
            public string Name { get; set; }
            public string LinkFileName { get; set; }
            public RemoteDebuggingPort RemoteDebuggingPort { get; set; }
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

                Host.MainWindow.BeginInvoke(new Action(() => { Environment.Exit(0); }));
                return false;
            }
            
            var harmony = new Harmony(typeof(WebAutoTypeRDPExt).Name);
            harmony.PatchAll();

            SprEngine.FilterPlaceholderHints.Add(CheckPasswordBoxPlaceholder);

            return true;
        }

        private void CacheInstalledAppBrowsers()
        {
            var appsFolderId = new Guid("{1e87508d-89c2-42f0-8a7e-645a0f50ca58}");
            var appsFolder = KnownFolderHelper.FromKnownFolderId(appsFolderId);
            
            foreach (var app in appsFolder.Where(
                   app => app.Properties.System.Link.TargetParsingPath.Value != null
                && app.Properties.System.Link.TargetParsingPath.Value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                && appBrowsersConfig.Any(appBrowserConfig => appBrowserConfig.Value.LinkFileName == app.Name.Replace((char)160, ' '))))
            {
                appBrowsers.Add(new AppBrowser
                {
                    Name = app.Name.Replace((char)160, ' '),
                    LinkFileName = app.Name,
                    ExecutablePath = app.Properties.System.Link.TargetParsingPath.Value
                });
            }
        }

        private void Setup()
        {
            TerminateBrowsers();

            foreach (var appBrowser in appBrowsers)
            {
                SetupBrowserShortcuts(appBrowser.LinkFileName, appBrowser.RemoteDebuggingPort);
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

        private void SetupBrowserShortcuts(string linkFileName, RemoteDebuggingPort devToolsPort)
        {
            var startMenuLinkPath = string.Format(@"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\{0}.lnk", linkFileName);
            var taskBarLinkPath = string.Format(@"{0}\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\{1}.lnk", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), linkFileName);

            UpdateLinkArguments(startMenuLinkPath, devToolsPort);
            UpdateLinkArguments(taskBarLinkPath, devToolsPort);
        }

        private void UpdateLinkArguments(string linkPath, RemoteDebuggingPort devToolsPort)
        {
            if (System.IO.File.Exists(linkPath))
            {
                var link = (IWshShortcut)type.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { linkPath });
                link.Arguments = Regex.Replace(link.Arguments, @"\s*[^\s]*\-\-remote\-debugging\-port=[^\s]*\s*", " ");
                link.Arguments = Regex.Replace(link.Arguments, @"\s*[^\s]*\-\-remote\-allow\-origins=[^\s]*\s*", " ");
                link.Arguments = string.Format("--remote-debugging-port=\"{0:D}\" --remote-allow-origins=* {1}", devToolsPort, link.Arguments.Trim());
                link.Arguments = link.Arguments.Trim();
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

        public static async Task<bool> PerformAutoType(ImageList icons)
        {
            await autoTypeSemaphore.WaitAsync();

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
                    MessageBox.Show(string.Format("The active browser is not supported:\n\n{0}", executablePath), pluginName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return false;
                }

                var debuggers = await GetDebuggers(appBrowser.RemoteDebuggingPort);

                // Conditions order matters
                if (   await TryPerformAutoType(icons, debuggers, IsBrowserUrlFocused, true)
                    || await TryPerformAutoType(icons, debuggers, IsBrowserUrlVisible, false))
                {
                    // Return "true" to harmony patch to NOT execute KeePass's method.
                    return true;
                }
            }
            catch (Exception ex)
            {
                if (ex is WebException)
                {
                    var result = MessageBox.Show("The active browser doesn't have a remote debugging port enabled.\n\nEither you didn't execute the plugin setup, the browser wasn't executed through a shortcut or another application/service started browser instances in the background that interfere with the plugin.\n\nYou can investigate based on the previous causes.\n\nDo you want to terminate any running browser instance?", pluginName, MessageBoxButtons.OKCancel, MessageBoxIcon.Error);

                    if (result == DialogResult.OK)
                    {
                        TerminateBrowsers();
                    }
                }
                else if (ex is JsonException || ex is KeyNotFoundException)
                {
                    // The json response structure from the remote debugging protocol has changed. The code has to be updated.
                    MessageBox.Show("The active browser's remote debugging protocol has changed.\n\nPlease contact the plugin's author.", pluginName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    throw;
                }
            }
            finally
            {
                autoTypeSemaphore.Release();
            }

            // Return "false" to harmony patch to execute KeePass's method normally.
            return false;
        }

        private static async Task<bool> TryPerformAutoType(ImageList icons, IEnumerable<Debugger> debuggers, Func<Debugger, Task<bool>> browserUrlValidator, bool canCheckPasswordBox)
        {
            var windowHandle = GetForegroundWindow();
            var activeWindowTitle = GetActiveWindowTitle(windowHandle);

            foreach (var debugger in debuggers)
            {
                if (activeWindowTitle.Contains(HttpUtility.HtmlDecode(debugger.title)) && await browserUrlValidator(debugger))
                {
                    var entries = FindMatchingEntries(debugger.url);

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

                                await PerformAutoType(debugger, entry, canCheckPasswordBox);
                            }

                            UIUtil.DestroyForm(autoTypeCtxForm);
                        }
                    }
                    else if (entries.Count() == 1)
                    {
                        var entry = entries.Single();

                        await PerformAutoType(debugger, entry, canCheckPasswordBox);
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
        private static async Task PerformAutoType(Debugger debugger, PwEntry entry, bool canCheckPasswordBox)
        {
            var autoTypeSequence = entry.GetAutoTypeSequence();
            var index = autoTypeSequence.IndexOf(CheckPasswordBoxPlaceholder, StringComparison.InvariantCultureIgnoreCase);

            string sequence;
            string remainder = null;

            if (canCheckPasswordBox && index > -1)
            {
                if (!await IsPasswordBoxFocused(debugger))
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
                if (await IsPasswordBoxFocused(debugger))
                {
                    AutoType.PerformIntoCurrentWindow(entry, Host.Database, remainder);
                }
            }
        }

        private static async Task<IEnumerable<Debugger>> GetDebuggers(RemoteDebuggingPort devToolsPort)
        {
            using (HttpClient client = new HttpClient())
            {
                var response = await client.GetAsync(string.Format("http://127.0.0.1:{0:D}/json", devToolsPort));

                if (response.IsSuccessStatusCode)
                {
                    var debuggers = JsonSerializer.Deserialize<IEnumerable<Debugger>>(await response.Content.ReadAsStringAsync());
                    debuggers = debuggers.Where(x => !string.IsNullOrEmpty(x.webSocketDebuggerUrl) && x.type == "page");

                    return debuggers;
                }
            }

            return Enumerable.Empty<Debugger>();
        }

        public class Debugger
        {
            public string title { get; set; }
            public string type { get; set; }
            public string url { get; set; }
            public string webSocketDebuggerUrl { get; set; }
        }

        private static async Task<string> Evaluate(Debugger debugger, string expression)
        {
            var message = new StringBuilder();
            expression = string.Format(@"{{""method"":""Runtime.evaluate"",""params"":{{""expression"":""{0}""}},""id"":1}}", expression);
            
            using (var ws = new ClientWebSocket())
            {
                var buffer = new byte[1024];

                await ws.ConnectAsync(new Uri(debugger.webSocketDebuggerUrl.Replace("localhost", "127.0.0.1")), CancellationToken.None);
                await ws.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(expression)), WebSocketMessageType.Text, true, CancellationToken.None);

                if (ws.State == WebSocketState.Open)
                {
                    WebSocketReceiveResult result;

                    do
                    {
                        result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
                        message.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));
                    } while (!result.EndOfMessage);

                    await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
                }
            }

            return message.ToString();
        }

        private static async Task<bool> IsBrowserUrlFocused(Debugger debugger)
        {
            var json = await Evaluate(debugger, "document.hasFocus()");

            var result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(result["result"]);
            result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(result["result"]);

            if (result["type"].GetString() == "boolean")
            {
                return result["value"].GetBoolean();
            }

            return false;
        }

        private static async Task<bool> IsBrowserUrlVisible(Debugger debugger)
        {
            var json = await Evaluate(debugger, "document.visibilityState");

            var result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(result["result"]);
            result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(result["result"]);

            if (result["type"].GetString() == "boolean")
            {
                return result["value"].GetString() == "visible";
            }

            return false;
        }

        private static async Task<bool> IsPasswordBoxFocused(Debugger debugger)
        {
            await RegisterGetActiveElementFunction(debugger);

            var json = await Evaluate(debugger, "kpGetActiveElement().type");

            var result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(result["result"]);
            result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(result["result"]);

            if (result["type"].GetString() == "string")
            {
                return result["value"].GetString() == "password";
            }

            return false;
        }

        // Create a JavaScript function that returns the active element of a page, regardless of iframe window or shadow root.
        private static async Task RegisterGetActiveElementFunction(Debugger debugger)
        {
            await Evaluate(debugger, @"
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
