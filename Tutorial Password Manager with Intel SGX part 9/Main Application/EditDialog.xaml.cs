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
    /// Interaction logic for EditDialog.xaml
    /// </summary>
    public partial class EditDialog : Window
    {
        private readonly PasswordItemDetails _pNewItem;
        private readonly PasswordManagerCore _mgr;
        private readonly MainWindow _main;

        public EditDialog(MainWindow mainIn, PasswordItemDetails pItem)
        {
            InitializeComponent();

            _main = mainIn;
            _mgr = _main.PasswordManager();

            if (pItem != null)
            {
                _pNewItem = new PasswordItemDetails(pItem.Index);
                txtEAccount.Text = pItem.Account;
                txtEURL.Text = pItem.UrLstring;
                txtELogin.Text = pItem.Login;
                txtEPassword.Text = "***************************";
                _pNewItem = pItem;
            }
        }

        private void btnOK_Click(object sender, RoutedEventArgs e)
        {
            // The main window actually attempts to update the
            // vault so no error handling is needed here.
            try
            {
                _pNewItem.Account = txtEAccount.Text;
                _pNewItem.Login = txtELogin.Text;
                _pNewItem.UrLstring = txtEURL.Text;
                DialogResult = true;
            }
            catch
            {
                DialogResult = false;
            }
        }

        public PasswordItemDetails RetriveEditAccount()
        {
            return _pNewItem;
        }

        private void btnSet_Click(object sender, RoutedEventArgs e)
        {
            // This form takes care of saving the password.
            var passwordDialog = new EditPassword(_pNewItem, _main);

            if (passwordDialog.ShowDialog() == false)
            {
                var rv = passwordDialog.Error;

                if (rv != PasswordManagerStatus.UserCancelled && rv != PasswordManagerStatus.OK)
                {
                    MessageBox.Show("Couldn't save password: " + MainWindow.ReturnErrorcode(rv));
                }
            }
        }

        private void btnView_Click(object sender, RoutedEventArgs e)
        {
            var wnd = GetWindow(this);
            var wih = new WindowInteropHelper(wnd);
            var hptr = wih.Handle;

            // If we lose the enclave, then our dialog window needs to be closed, and we
            // let the main window handle it.
            var rv = _mgr.accounts_view_password(_pNewItem.Index, hptr);

            if (rv == PasswordManagerStatus.RecreatedEnclave || rv == PasswordManagerStatus.LostEnclave)
            {
                DialogResult = false;
                _Close();
            }
            else if (rv != PasswordManagerStatus.OK)
            {
                MessageBox.Show("Couldn't view password: " + MainWindow.ReturnErrorcode(rv));
            }
        }

        private void Window_SourceInitialized(object sender, EventArgs e)
        {
            // Start listening to power change events. WPF doesn't have a nice control
            // for this.
            _main.AddPowerHook(Acct_Power_Hook);
        }

        private IntPtr Acct_Power_Hook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
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
            _main.RemovePowerHook(Acct_Power_Hook);
        }

        private void _Close()
        {
            try
            {
                Close();
            }
            catch (InvalidOperationException)
            {
                // We're already closing so we can ignore this.  
            }
        }
    }
}
