// Copyright 2016 Intel Corporation.

// The source code, information and material ("Material") contained herein is
// owned by Intel Corporation or its suppliers or licensors, and title to such
// Material remains with Intel Corporation or its suppliers or licensors. The
// Material contains proprietary information of Intel or its suppliers and
// licensors. The Material is protected by worldwide copyright laws and treaty
// provisions. No part of the Material may be used, copied, reproduced, modified,
// published, uploaded, posted, transmitted, distributed or disclosed in any way
// without Intel's prior express written permission. No license under any patent,
// copyright or other intellectual property rights in the Material is granted to
// or conferred upon you, either expressly, by implication, inducement, estoppel
// or otherwise. Any license under such intellectual property rights must be
// express and approved by Intel in writing.

// Include any supplier copyright notices as supplier requires Intel to use.

// Include supplier trademarks or logos as supplier requires Intel to use,
// preceded by an asterisk. An asterisked footnote can be added as follows:
// *Third Party trademarks are the property of their respective owners.

// Unless otherwise agreed by Intel in writing, you may not remove or alter this
// notice or any other notice embedded in Materials by Intel or Intel's suppliers
// or licensors in any way.

using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.IO;
using System.Windows.Interop;
using System.Security;
using System.Runtime.InteropServices;
using ExtensionMethods;
using PasswordManager;

namespace Password_manager
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public static List<PasswordItemDetails> ItemDetails = new List<PasswordItemDetails>();
        private string _workingVault;
        private readonly PasswordManagerCore _mgr = new PasswordManagerCore();
        private bool _bCreateNewVault;
        private readonly UserPrefs _prefs = new UserPrefs();
        private HwndSource _hsrc;

        public enum PasswordDisplayStatus
        {
            BadFile = 10,
            CantUpdate = 15,
            Clipboard = 14,
            Exists = 5,
            IncorrectVersion = 9,
            Invalid = 8,
            MemoryAllocation = 2,
            NoChange = 1,
            NoPermission = 6,
            NotFound = 7,
            Ok = 0,
            PasswordIncorrect = 13,
            RandomGenerator = 11,
            Range = 4,
            Size = 3,
            UserCancelled = 12,
            WriteFailed = 16,
        }

        public PasswordManagerCore PasswordManager() { return _mgr; }

        public MainWindow()
        {
            var sgxfeature = new FeatureSupport();
            InitializeComponent();

            // In the SGX branch, the lock timeout is also stored in our password vault. 
            _mgr.set_lock_timeout((ushort)_prefs.LockDelay);

            // Detect SGX support
            if (sgxfeature.is_supported() == 1)
            {
                // We support SGX, but are we enabled or is further action required?
                if (sgxfeature.is_enabled() == 1)
                {
                    _mgr.set_sgx_support();
                }
                else if (sgxfeature.reboot_required() == 1)
                {
                    MessageBox.Show("Intel­® SGX is supported on this system, but a reboot is required to enable it. This application will run without Intel® SGX support for now.", "Intel® SGX not enabled");
                }
                else if (sgxfeature.bios_enable_required() == 1)
                {
                    MessageBox.Show("Intel® SGX is supported on this system, but it needs to be manually enabled in the BIOS. This application will run without Intel® SGX for now.", "Intel® SGX not enabled");
                }
            }
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void ListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (lbPasswordList.SelectedItem != null)
            {
                txtAccount.Text = (lbPasswordList.SelectedItem as PasswordItemDetails).Account;
                txtURL.Text = (lbPasswordList.SelectedItem as PasswordItemDetails).UrLstring;
                txtLogin.Text = (lbPasswordList.SelectedItem as PasswordItemDetails).Login;
            }
        }

        public static string ReturnErrorcode(int rv)
        {
            var passDisplayStatus = (PasswordDisplayStatus)rv;
            var stringValue = passDisplayStatus.ToString();
            return stringValue;
        }

        private void unlock_Click(object sender, RoutedEventArgs e)
        {
            uint count = 0;
            var randpass = new SecureString();
            var emptypass = new SecureString();
            var ssname = new SecureString();
            var login = new SecureString();
            var url = new SecureString();
            var accountpass = new SecureString();
            int rv;
            var masterpass = txtpasswordbox.SecurePassword;

            if (masterpass.Length == 0)
            {
                MessageBox.Show("Please enter Master Password to Unlock the vault: ");
                return;
            }

            if (_bCreateNewVault)
            {
                rv = _mgr.set_master_password(masterpass, masterpass);

                if (rv != PasswordManagerStatus.OK)
                {
                    MessageBox.Show("Setting master password failed: " + ReturnErrorcode(rv));
                    return;
                }
            }
            else
            {
                rv = _mgr.vault_unlock(masterpass);

                if (rv != PasswordManagerStatus.OK)
                {
                    MessageBox.Show("Couldn't unlock vault: " + ReturnErrorcode(rv));
                    return;
                }
            }

            txtpasswordbox.Clear();
            masterpass.Clear();
            pmangerPanel.Visibility = Visibility.Collapsed;

            rv = _mgr.accounts_get_count(ref count);

            if (rv != PasswordManagerStatus.OK)
            {
                MessageBox.Show("Couldn't get number of accounts from password vault: " + ReturnErrorcode(rv));
                return;
            }

            if (!_bCreateNewVault)
            {
                for (uint i = 0; i < count; ++i)
                {
                    rv = _mgr.accounts_get_info(i, ref ssname, ref login, ref url);

                    if (rv != PasswordManagerStatus.OK)
                    {
                        MessageBox.Show("Failed getting account info: " + ReturnErrorcode(rv));
                        return;
                    }

                    ItemDetails.Add(new PasswordItemDetails(i) { SsAccount = ssname, SsUrLstring = url, SsLogin = login });
                }
            }

            for (var i = count; i < 8; ++i)
            {
                ItemDetails.Add(new PasswordItemDetails(i));
            }

            lbPasswordList.ItemsSource = ItemDetails;
            lbPasswordList.Background = SystemColors.ControlLightLightBrush;
            lbPasswordList.SelectedItem = lbPasswordList.Items.GetItemAt(0);
            btnEditAccount.IsEnabled = true;
            btnViewPassword.IsEnabled = true;
            btnCopyPassword.IsEnabled = true;
            mnCopyto.IsEnabled = true;
            btnCreateVault.IsEnabled = false;
            btnOpenVault.IsEnabled = false;
            mnOpen.IsEnabled = false;
            mnNew.IsEnabled = false;
            btnlock.IsEnabled = true;
            mnLock.IsEnabled = true;
            btnUnlock.IsEnabled = false;
            mnChangePassword.IsEnabled = true;
            btnViewPassword.Content = "View Password";
        }

        private void btnOpenVault_Click(object sender, RoutedEventArgs e)
        {
            OpenExistingVault();
        }

        private void OpenExistingVault()
        {
            var randpass = new SecureString();
            var emptypass = new SecureString();
            var name = new SecureString();
            var login = new SecureString();
            var url = new SecureString();

            _bCreateNewVault = false;

            var openFileDialog1 = new OpenFileDialog
            {
                Filter = "Vault|*.vlt",
                FilterIndex = 1,
                Multiselect = true
            };

            var userClickedOk = openFileDialog1.ShowDialog();

            if (userClickedOk == true)
            {
                var path = openFileDialog1.InitialDirectory + openFileDialog1.FileName;
                //Backup(path);               

                var rv = _mgr.vault_open(path);

                if (rv != PasswordManagerStatus.OK)
                {
                    MessageBox.Show("Failed opening vault file: " + ReturnErrorcode(rv));
                    return;
                }

                _workingVault = path;
                pmangerPanel.Visibility = Visibility.Visible;
            }
        }

        private void btnCreateVault_Click(object sender, RoutedEventArgs e)
        {
            CreateNewVault();
        }

        private void CreateNewVault()
        {
            var dialog = new SaveFileDialog()
            {
                Filter = "Vault|*.vlt"
            };

            if (dialog.ShowDialog() == true)
            {
                var path = dialog.FileName;

                if (File.Exists(path))
                {
                    File.Delete(path);
                }

                var rv = _mgr.vault_create(path);

                if (rv != PasswordManagerStatus.OK)
                {
                    MessageBox.Show("Failed creating vault file: " + ReturnErrorcode(rv));
                    return;
                }

                _txtBlock.Text = "Set a master password for the Vault file.";
                btnUnlock.Content = "Create Vault";

                _bCreateNewVault = true;
                pmangerPanel.Visibility = Visibility.Visible;
            }
        }

        private void btnEditAccount_Click(object sender, RoutedEventArgs e)
        {
            if (lbPasswordList.SelectedItem != null)
            {
                var i = lbPasswordList.SelectedIndex;
                var pItem = lbPasswordList.SelectedItem as PasswordItemDetails;
                var inputDialog = new EditDialog(this, pItem);

                if (inputDialog.ShowDialog() == true)
                {
                    pItem = inputDialog.RetriveEditAccount();

                    if (pItem != null)
                    {
                        // The password dialog window takes care of saving the password
                        var rv = _mgr.accounts_set_info((uint)i, pItem.SsAccount, pItem.SsLogin, pItem.SsUrLstring);

                        if (rv != PasswordManagerStatus.OK)
                        {
                            // Don't update the display if we can't save the new info
                            MessageBox.Show("Failed setting account info: " + ReturnErrorcode(rv));
                            return;
                        }

                        txtAccount.Text = pItem.Account;
                        txtURL.Text = pItem.UrLstring;
                        txtLogin.Text = pItem.Login;

                        ItemDetails[i].SsAccount = pItem.SsAccount;
                        ItemDetails[i].SsUrLstring = pItem.SsUrLstring;
                        ItemDetails[i].SsLogin = pItem.SsLogin;

                        lbPasswordList.ItemsSource = ItemDetails;
                        lbPasswordList.Items.Refresh();
                    }
                }
            }
        }

        private void btnViewPassword_Click(object sender, RoutedEventArgs e)
        {
            if (lbPasswordList.SelectedItem != null)
            {
                var wnd = GetWindow(this);
                var wih = new WindowInteropHelper(wnd);
                var hptr = wih.Handle;
                var rv = _mgr.accounts_view_password((uint)lbPasswordList.SelectedIndex, hptr);

                if (rv != PasswordManagerStatus.OK)
                {
                    MessageBox.Show("Couldn't view password: " + ReturnErrorcode(rv));
                }
            }
        }

        private void btnCopyPassword_Click(object sender, RoutedEventArgs e)
        {
            CopypasswordClipboard();
        }

        private void CopypasswordClipboard()
        {
            if (lbPasswordList.SelectedItem != null)
            {
                var i = lbPasswordList.SelectedIndex;
                var y = (uint)i;
                var rv = _mgr.accounts_password_to_clipboard(y);

                if (rv != PasswordManagerStatus.OK)
                {
                    MessageBox.Show("Failed to copy password to clipboard: " + ReturnErrorcode(rv));
                }
            }
        }

        private void btnlock_Click(object sender, RoutedEventArgs e)
        {
            LockVault();
        }

        private void LockVault()
        {
            LockVault(true);
        }

        private void LockVault(bool explictLock)
        {
            lbPasswordList.ItemsSource = null;
            lbPasswordList.Items.Clear();
            lbPasswordList.Background = SystemColors.ControlBrush;
            txtAccount.Text = string.Empty;
            txtURL.Text = string.Empty;
            txtLogin.Text = string.Empty;
            ItemDetails.Clear();

            if (explictLock)
            {
                _mgr.vault_lock();
            }

            btnEditAccount.IsEnabled = false;
            btnViewPassword.IsEnabled = false;
            btnCopyPassword.IsEnabled = false;
            mnCopyto.IsEnabled = false;
            btnCreateVault.IsEnabled = true;
            btnOpenVault.IsEnabled = true;
            mnOpen.IsEnabled = true;
            mnNew.IsEnabled = true;
            _bCreateNewVault = false;
            btnlock.IsEnabled = false;
            mnLock.IsEnabled = false;
            btnUnlock.IsEnabled = true;
            pmangerPanel.Visibility = Visibility.Visible;
            txtpasswordbox.Clear();
            txtpasswordbox.Focus();

            _txtBlock.Text = "Enter your Master Password to Unlock your Vault ";
            btnUnlock.Content = "UnLock";
            mnChangePassword.IsEnabled = false;
        }

        private void ChangePassword_Click(object sender, RoutedEventArgs e)
        {
            var editPasswordDlg = new ChangePassword(this);
            var result = editPasswordDlg.ShowDialog();

            // Don't print a message if the result is null (meaning the
            // user canceled or the system went to sleep).

            if (result == true)
            {
                MessageBox.Show("Password changed");
            }
            else if (editPasswordDlg.ShowDialog() == false)
            {
                MessageBox.Show("Changing master password failed: " + ReturnErrorcode(editPasswordDlg.ErrorCode));
            }
        }

        private void Lock_Click_1(object sender, RoutedEventArgs e)
        {
            LockVault();
        }

        private void mnNew_Click(object sender, RoutedEventArgs e)
        {
            CreateNewVault();
        }

        private void mnOpen_Click(object sender, RoutedEventArgs e)
        {
            OpenExistingVault();
        }

        private void mnCopyto_Click(object sender, RoutedEventArgs e)
        {
            CopypasswordClipboard();
        }

        private void mnOptions_Click(object sender, RoutedEventArgs e)
        {
            var optDlg = new OptionsDialog(_prefs);

            if (optDlg.ShowDialog() == true)
            {
                _prefs.SavePrefs();
                _mgr.set_lock_timeout((ushort)_prefs.LockDelay);
            }
        }

        // Start listening to power change events. WPF doesn't have a nice control
        // for this.
        public void AddPowerHook(HwndSourceHook hook)
        {
            _hsrc.AddHook(hook);
        }

        public void RemovePowerHook(HwndSourceHook hook)
        {
            _hsrc.RemoveHook(hook);
        }

        private void Window_SourceInitialized(object sender, EventArgs e)
        {
            // Note: This is not robust. What if hWnd changes? We really should
            // be listening for that on PropertyChanged.
            _hsrc = HwndSource.FromHwnd(new WindowInteropHelper(this).Handle);
            AddPowerHook(Main_Power_Hook);
        }

        private IntPtr Main_Power_Hook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            // C# doesn't have definitions for power messages, so we'll get them via C++/CLI. It returns a
            // simple UInt16 that defines only the things we care about.
            var pmsg = PowerManagement.message(msg, wParam, lParam);

            if (pmsg == PowerManagementMessage.Suspend)
            {
                _mgr.suspend();
                handled = true;
            }
            else if (pmsg == PowerManagementMessage.Resume)
            {
                var vstate = _mgr.resume();

                if (vstate == ResumeVaultState.Locked)
                {
                    LockVault();
                }

                handled = true;
            }

            return IntPtr.Zero;
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            RemovePowerHook(this.Main_Power_Hook);
        }
    }

    public class PasswordItemDetails
    {
        public SecureString SsAccount { get; set; }
        public SecureString SsUrLstring { get; set; }
        public SecureString SsLogin { get; set; }
        public uint Index { get; set; }
        public static string Emptystring = "";

        public string Account
        {
            get
            {
                return SsAccount == null ? Emptystring : SsAccount.ToInsecureString();
            }
            set
            {
                SsAccount = value.ToSecureString();
            }
        }

        public string UrLstring
        {
            get
            {
                return SsUrLstring == null ? Emptystring : SsUrLstring.ToInsecureString();
            }
            set
            {
                SsUrLstring = value.ToSecureString();
            }
        }

        public string Login
        {
            get
            {
                return SsLogin == null ? Emptystring : SsLogin.ToInsecureString();
            }
            set
            {
                SsLogin = value.ToSecureString();
            }
        }

        public string DisplayName => $"Account {Index}: {Account}";

        public PasswordItemDetails(uint i)
        {
            Index = i;
        }
    }
}

namespace ExtensionMethods
{
    public static class StringExtension
    {
        public static SecureString ToSecureString(this string stdString)
        {
            if (stdString == null)
            {
                throw new ArgumentNullException(nameof(stdString));
            }

            unsafe
            {
                fixed (char* cp = stdString)
                {
                    var secureString = new SecureString(cp, stdString.Length);
                    secureString.MakeReadOnly();
                    return secureString;
                }
            }

        }
    }

    public static class SecureStringExtension
    {
        // A flower dies every time this method is called.
        public static string ToInsecureString(this SecureString ss)
        {
            if (ss == null)
            {
                throw new ArgumentNullException(nameof(ss));
            }

            var unmanagedString = IntPtr.Zero;

            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(ss);
                return Marshal.PtrToStringUni(unmanagedString);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }
    }
}
