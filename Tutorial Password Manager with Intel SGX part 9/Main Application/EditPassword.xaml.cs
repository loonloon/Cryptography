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

using System;
using System.Windows;
using System.Security;
using PasswordManager;
using System.Windows.Interop;

namespace Password_manager
{
    /// <summary>
    /// Interaction logic for EditPassword.xaml
    /// </summary>
    public partial class EditPassword : Window
    {
        public int Error { get; set; }
        private readonly PasswordManagerCore _mgr;
        private readonly MainWindow _main;
        private readonly uint _idx;

        public EditPassword(PasswordItemDetails pItem, MainWindow mainIn)
        {
            InitializeComponent();

            _main = mainIn;
            btnSavenew.IsEnabled = false;
            _idx = pItem.Index;
            Error = PasswordManagerStatus.UserCancelled;
            _mgr = _main.PasswordManager();

            if (pItem != null)
            {
                txtPassfor.Text = pItem.Login + " at " + pItem.Account;
            }
        }

        private void btnGenerate_Click(object sender, RoutedEventArgs e)
        {
            var randpass = new SecureString();
            var len = GeneratePassword(randpass);

            if (len > 0)
            {
                try
                {
                    DialogResult = SavePassword(randpass);
                }
                catch (InvalidOperationException)
                {

                }

                randpass.Clear();
                _Close();
            }

            randpass.Clear();
        }

        private ushort GeneratePassword(SecureString randpass)
        {
            int rv;
            ushort len;

            try
            {
                len = Convert.ToUInt16(txtnoChars.Text);
            }
            catch
            {
                MessageBox.Show("Invalid password length");
                return 0;
            }

            if (len < 1 | len > 255)
            {
                MessageBox.Show("Length must be between 1 and 255 characters");
                return 0;
            }

            // Get a handle to our window so we can pass it to the native function
            var wnd = GetWindow(this);
            var wih = new WindowInteropHelper(wnd);
            var hptr = wih.Handle;

            if (chChars.IsChecked == true)
            {
                rv = _mgr.generate_and_view_password(len, PasswordFlag.All, ref randpass, hptr);
            }
            else
            {
                rv = _mgr.generate_and_view_password(len, PasswordFlag.UpperCase | PasswordFlag.LowerCase | PasswordFlag.Numerals, ref randpass, hptr);
            }

            if (rv == PasswordManagerStatus.UserCancelled)
            {
                return 0;
            }

            if (rv != PasswordManagerStatus.OK)
            {
                MessageBox.Show("Error generating password: " + rv.ToString());
                return 0;
            }

            return len;
        }

        private void btnSavenew_Click(object sender, RoutedEventArgs e)
        {
            if (SavePassword(txtNewPass.SecurePassword))
            {
                DialogResult = true;
            }
            else if (Error != PasswordManagerStatus.UserCancelled)
            {
                DialogResult = false;
            }

            _Close();
        }


        private void txtNewPassSave_Changed(object sender, RoutedEventArgs e)
        {
            btnSavenew.IsEnabled = true;
        }

        private bool SavePassword(SecureString newpass)
        {
            Error = _mgr.accounts_set_password(_idx, newpass);
            newpass.Clear();
            txtNewPass.SecurePassword.Clear();
            return Error == PasswordManagerStatus.OK;
        }

        private void Window_SourceInitialized(object sender, EventArgs e)
        {
            // Start listening to power change events. WPF doesn't have a nice control
            // for this.
            _main.AddPowerHook(Passwd_Power_Hook);
        }

        private IntPtr Passwd_Power_Hook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            // C# doesn't have definitions for power messages, so we'll get them via C++/CLI. It returns a
            // simple UInt16 that defines only the things we care about.
            var pmsg = PowerManagement.message(msg, wParam, lParam);

            if (pmsg == PowerManagementMessage.Resume || pmsg == PowerManagementMessage.Suspend)
            {
                // Raise the Closing event which will close our window
                // Don't set handled because we want other windows to process this signal, too.
                _Close();
            }

            return IntPtr.Zero;
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            _main.RemovePowerHook(Passwd_Power_Hook);
        }

        void _Close()
        {
            try
            {
                Close();
            }
            catch (InvalidOperationException)
            {
            }
        }
    }
}
