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
using System.Windows.Interop;
using PasswordManager;

namespace Password_manager
{
    /// <summary>
    /// Interaction logic for ChangePassword.xaml
    /// </summary>
    public partial class ChangePassword : Window
    {
        private readonly PasswordManagerCore _mgr;
        private readonly MainWindow _main;
        public int ErrorCode { get; set; }

        public ChangePassword(MainWindow mainIn)
        {
            InitializeComponent();
            _main = mainIn;
            _mgr = _main.PasswordManager();
            // This isn't used, but it's a good "nothing has been attempted" initial value
            ErrorCode = PasswordManagerStatus.UserCancelled;
        }

        private void btnPassSave_Click(object sender, RoutedEventArgs e)
        {
            ErrorCode = _mgr.change_master_password(txtOldPass.SecurePassword, txtNewPass.SecurePassword, txtConfirmPass.SecurePassword);
            txtOldPass.SecurePassword.Clear();
            txtNewPass.SecurePassword.Clear();
            txtConfirmPass.SecurePassword.Clear();

            if (ErrorCode == PasswordManagerStatus.OK)
            {
                DialogResult = true;
            }
            else if (ErrorCode == PasswordManagerStatus.Mismatch)
            {
                MessageBox.Show("New password and confirmed password do not match", "Passwords do not match", MessageBoxButton.OK);
                // Don't close the window
                return;
            }
            else if (ErrorCode == PasswordManagerStatus.NoPermission)
            {
                MessageBox.Show("Password incorrect", "Password incorrect", MessageBoxButton.OK);
                // Don't close the window.
                return;
            }
            else
            {
                // Close the window and let the parent send the error message
                DialogResult = false;
            }

            _Close();
        }

        private void btnPassCancel_Click(object sender, RoutedEventArgs e)
        {
            txtOldPass.SecurePassword.Clear();
            txtNewPass.SecurePassword.Clear();
            txtConfirmPass.SecurePassword.Clear();

            DialogResult = false;
            _Close();
        }

        private void Window_SourceInitialized(object sender, EventArgs e)
        {
            // Start listening to power change events. WPF doesn't have a nice control
            // for this.
            _main.AddPowerHook(Power_Hook);
        }

        private IntPtr Power_Hook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            // C# doesn't have definitions for power messages, so we'll get them via C++/CLI. It returns a
            // simple UInt16 that defines only the things we care about.
            var pmsg = PowerManagement.message(msg, wParam, lParam);

            if (pmsg == PowerManagementMessage.Resume || pmsg == PowerManagementMessage.Suspend)
            {
                // Raise the Closing event which will close our window
                _Close();
                handled = true;
            }

            return IntPtr.Zero;
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            _main.RemovePowerHook(new HwndSourceHook(Power_Hook));
        }

        private void _Close()
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
