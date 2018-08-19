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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security;
using System.Runtime.InteropServices;
using System.Threading;
using PasswordManager;

namespace PasswordManagerTest
{
    public class TestSuite {
        TestSetup setup;
        PasswordManagerCore mgr;
        String working_vault;
        OutputCallback output;

        public TestSuite (TestSetup setup_in)
        {
            mgr = new PasswordManagerCore();
            setup = setup_in;
            if (setup.getSGXSupport()) mgr.set_sgx_support();

            output = setup.getOutputCallback();
        }

        public bool RunAll()
        {
           try {
                this.Initialize();
                //this.RunNewVault();
                this.RunExistingVault();
           }
           catch {                
                return false;
           }

           //output("Sleeping for 15 seconds to let clipboard timers finish...");
           //Thread.Sleep(15000);
           return true;
        }

        public void Banner (string hdr)
        {
            output("=========================================================");
            output(hdr);
            output("=========================================================");
        }

        public bool Initialize()
        {
            if (!Directory.Exists(setup.UserTestDir))
            {
                output(String.Format("Creating test directory {0}", setup.UserTestDir));
                try
                {
                    Directory.CreateDirectory(setup.UserTestDir);
                }
                catch (Exception e)
                {
                    output(String.Format("Error: {0}", e.ToString()));
                    return false;
                }
            }

            return true;
        }

        public void Backup(String path)
        {
            String orig;

            working_vault = path;
            orig= Path.Combine(Path.GetDirectoryName(path), Path.GetFileNameWithoutExtension(path) + "_orig.vlt");
            output(String.Format("Backing up original vault file {0} to {1}", path, orig));
            try
            {
                File.Copy(path, orig);
            }
            catch { }
        }

        public void Restore ()
        {
            String path = working_vault;

            mgr.vault_lock();

            if (path.Length > 0)
            {
                String orig = Path.Combine(Path.GetDirectoryName(path), Path.GetFileNameWithoutExtension(path) + "_orig.vlt");
                String mod = Path.Combine(Path.GetDirectoryName(path), Path.GetFileNameWithoutExtension(path) + "_modified.vlt");

                output(String.Format("Copying modified vault to {0}", mod));
                output(String.Format("Restoring original vault file from {0} to {1}", orig, path));
                try
                {
                    File.Copy(path, mod, true);
                    File.Copy(orig, path, true);
                }
                catch { }
                working_vault = "";
            } 
        }

        void Assert (bool received, bool expected)
        {
            output(String.Format("    Expected {0}, received {1}...>>> ", expected, received), false);
            AssertResult(expected == received, (received)?"TRUE" : "FALSE");
        }
        void Assert (int received, int expected)
        {
            output(String.Format("    Expected {0}, received {1}...>>> ", expected, received), false);
            AssertResult(expected == received, mgr.error_msg(received));
        }

        void AssertResult (bool result, String message)
        {
            if (!result)
            {
                output("FAIL <<<");
                output("Error: ", false);
                output(message);
                Restore();
                throw new System.ArgumentException("Test failure");
            }
            output("PASS <<<");
        }

        string SStoString (SecureString ss)
        {
            IntPtr ssp = Marshal.SecureStringToBSTR(ss);
            string st = Marshal.PtrToStringBSTR(ssp);
            Marshal.ZeroFreeBSTR(ssp);
            return st;
        }

        SecureString StoSecureString (String s)
        {
            SecureString ss= new SecureString();
            foreach (char c in s) { ss.AppendChar(c); }
            return ss;
        }

        // http://stackoverflow.com/questions/4502676/c-sharp-compare-two-securestrings-for-equality
        // SwDevMan81

        Boolean SecureStringEqual(SecureString secureString1, SecureString secureString2)
        {
            if (secureString1 == null)
            {
                throw new ArgumentNullException("s1");
            }
            if (secureString2 == null)
            {
                throw new ArgumentNullException("s2");
            }

            if (secureString1.Length != secureString2.Length)
            {
                return false;
            }

            IntPtr ss_bstr1_ptr = IntPtr.Zero;
            IntPtr ss_bstr2_ptr = IntPtr.Zero;

            try
            {
                ss_bstr1_ptr = Marshal.SecureStringToBSTR(secureString1);
                ss_bstr2_ptr = Marshal.SecureStringToBSTR(secureString2);

                String str1 = Marshal.PtrToStringBSTR(ss_bstr1_ptr);
                String str2 = Marshal.PtrToStringBSTR(ss_bstr2_ptr);

                return str1.Equals(str2);
            }
            finally
            {
                if (ss_bstr1_ptr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(ss_bstr1_ptr);
                }

                if (ss_bstr2_ptr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(ss_bstr2_ptr);
                }
            }
        }

        //----------------------------------------------------------------------
        // Vault read tests
        //----------------------------------------------------------------------

        public bool RunExistingVault ()
        {
            string path;
            int rv = 0;
            uint count = 0;
            SecureString randpass = new SecureString();
            SecureString emptypass = new SecureString();
            SecureString name = new SecureString();
            SecureString login = new SecureString();
            SecureString url = new SecureString();
            SecureString accountpass = new SecureString();
            SecureString mpass_old, mpass_new;
            string mpass_old_st = "An enticing aroma of fruit flavors accented by licorice.";
            string mpass_new_st = "Significant understanding is ever present.";

            mpass_old = StoSecureString(mpass_old_st);
            mpass_new = StoSecureString(mpass_new_st);

            Banner("EXISTING VAULT TESTS");

            path = setup.VaultPath("reference");
            output(String.Format("Checking for reference vault {0}", path));
            Assert(File.Exists(path), true);

            // Make a copy of our original vault file which we can restore later.
            Backup(path);

            output(String.Format("Create new vault on top of existing vault {0}", path));
            rv = mgr.vault_create(path);
            Assert(rv, PasswordManagerStatus.Exists);

            output(String.Format("Opening vault {0}", path));
            rv = mgr.vault_open(path);
            Assert(rv, PasswordManagerStatus.OK);

            output(String.Format("Generate password"));
            rv = mgr.generate_password(16, PasswordFlag.UpperCase | PasswordFlag.LowerCase | PasswordFlag.Numerals, ref randpass);
            Assert(rv, PasswordManagerStatus.OK);
            output(String.Format("Password: {0}", SStoString(randpass)));

            output("Set master password");
            rv = mgr.set_master_password(randpass, randpass);
            Assert(rv, PasswordManagerStatus.NoPermission);

            output("Change master password");
            rv = mgr.change_master_password(new SecureString(), randpass, randpass);
            Assert(rv, PasswordManagerStatus.NoPermission);

            output("Read accounts without unlocking");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.NoPermission);

            output("Read account password without unlocking");
            rv = mgr.accounts_get_password(0, ref randpass);
            Assert(rv, PasswordManagerStatus.NoPermission);

            output("Read account without unlocking");
            rv = mgr.accounts_get_info(0, ref name, ref login, ref url);
            Assert(rv, PasswordManagerStatus.NoPermission);

            output("Update account without unlocking");
            rv = mgr.accounts_set_info(0, name, login, url);
            Assert(rv, PasswordManagerStatus.NoPermission);

            output("Unlock with wrong password");
            rv = mgr.vault_unlock(randpass);
            Assert(rv, PasswordManagerStatus.PasswordIncorrect);

            output("Unlock vault");
            rv = mgr.vault_unlock(mpass_old);
            Assert(rv, PasswordManagerStatus.OK);

            output("Sleeping for 30 seconds. Memory dump NOW");
            Thread.Sleep(30000);


            output("Set master password");
            rv = mgr.set_master_password(randpass, randpass);
            Assert(rv, PasswordManagerStatus.Invalid);

            output("Change master password to itself");
            rv = mgr.change_master_password(mpass_old, mpass_old, mpass_old);
            Assert(rv, PasswordManagerStatus.NoChange);

            output("Read accounts");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.OK);
            output(String.Format("{0} accounts", count));
            Assert((int)count, 3);

            for (uint i = 0; i < count; ++i)
            {
                output(String.Format("Account {0}:", i));
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("    Name = '{0}'", SStoString(name)));
                output(String.Format("   Login = '{0}'", SStoString(login)));
                output(String.Format("     URL = '{0}'", SStoString(url)));

                rv = mgr.accounts_get_password(i, ref accountpass);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("Password = '{0}'", SStoString(accountpass)));
            }

            // Chenge all the account passwords to random ones

            for (ushort i = 0; i < count; ++i)
            {
                output(String.Format("Generating new password for account {0}", i));
                rv = mgr.generate_password(16, PasswordFlag.All, ref randpass);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("Password {0}: '{1}'", i, SStoString(randpass)));

                output(String.Format("Changing account password for account {0}", i));
                rv = mgr.accounts_set_password(i, randpass);
                Assert(rv, PasswordManagerStatus.OK);

                output(String.Format("Getting new password for account {0}", i));
                rv = mgr.accounts_get_password(i, ref accountpass);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("New password = '{0}'", SStoString(accountpass)));
                output(String.Format("Comparing generated password '{0}' to assigned password '{1}'", SStoString(randpass), SStoString(accountpass)));
                Assert(SecureStringEqual(randpass, accountpass), true);
            }

            // Try account that doesn't exist...

            output(String.Format("Fetching undefined account 5:", 5));
            rv = mgr.accounts_get_info(5, ref name, ref login, ref url);
            Assert(rv, PasswordManagerStatus.OK);
            output(String.Format("    Name = {0}", SStoString(name)));
            output(String.Format("   Login = {0}", SStoString(login)));
            output(String.Format("     URL = {0}", SStoString(url)));

            output("Fetch password for account 5 to clipboard");
            rv = mgr.accounts_get_password(5, ref accountpass);
            Assert(rv, PasswordManagerStatus.OK);
            output(String.Format("Password = {0}", SStoString(accountpass)));
            output(String.Format("Comparing empty password to undefined account password {0}", SStoString(accountpass)));
            Assert(SecureStringEqual(emptypass, accountpass), true);

            output("Copy password for account 5 to clipboard");
            rv = mgr.accounts_password_to_clipboard(5);
            Assert(rv, PasswordManagerStatus.OK);

            // ...and is out of range
            output("Copy password for account 105 to clipboard");
            rv = mgr.accounts_password_to_clipboard(105);
            Assert(rv, PasswordManagerStatus.Range);

            output("Copy password for account 1 to clipboard");
            rv = mgr.accounts_password_to_clipboard(1);
            Assert(rv, PasswordManagerStatus.OK);

            output("Copy password for account 2 to clipboard");
            rv = mgr.accounts_password_to_clipboard(2);
            Assert(rv, PasswordManagerStatus.OK);

            // Set account information

            {
                // Replace existing
                UInt32 i = 2;

                SecureString newname = StoSecureString("AOL");
                SecureString newlogin = StoSecureString("aoluser");
                SecureString newurl = StoSecureString("http://aol.com/");
                output(String.Format("Write new account information for account {0}", i));
                rv = mgr.accounts_set_info(i, newname, newlogin, newurl);
                Assert(rv, PasswordManagerStatus.OK);

                output(String.Format("Get new account information for account {0}:", i));
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("    Name = {0} (should be {1})", SStoString(name), SStoString(newname)));
                Assert(SecureStringEqual(name, newname), true);
                output(String.Format("   Login = {0} (should be {1})", SStoString(login), SStoString(newlogin)));
                Assert(SecureStringEqual(login, newlogin), true);
                output(String.Format("     URL = {0} (should be {1})", SStoString(url), SStoString(newurl)));
                Assert(SecureStringEqual(url, newurl), true);
            }

            {
                // Set undefined with partial data
                UInt32 i = 6;

                SecureString newname = StoSecureString("Non-ASCII chars «ταБЬℓσ»");
                SecureString newlogin = StoSecureString("");
                SecureString newurl = StoSecureString("http://unicodetest.net/");
                output(String.Format("Write new account information for account {0}", i));
                rv = mgr.accounts_set_info(i, newname, newlogin, newurl);
                Assert(rv, PasswordManagerStatus.OK);

                output(String.Format("Get new account information for account {0}:", i));
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("    Name = {0} (should be {1})", SStoString(name), SStoString(newname)));
                Assert(SecureStringEqual(name, newname), true);
                output(String.Format("   Login = {0} (should be {1})", SStoString(login), SStoString(newlogin)));
                Assert(SecureStringEqual(login, newlogin), true);
                output(String.Format("     URL = {0} (should be {1})", SStoString(url), SStoString(newurl)));
                Assert(SecureStringEqual(url, newurl), true);
            }

            // Change the master password

            output("Change master password");
            rv = mgr.change_master_password(mpass_old, mpass_new, mpass_new);
            Assert(rv, PasswordManagerStatus.OK);

            // Lock the vault

            output("Lock the vault");
            mgr.vault_lock();
            Assert(rv, PasswordManagerStatus.OK);

            // Now try and read something back.

            output("Read accounts  after locking");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.NoPermission);

            output("Read account password after locking");
            rv = mgr.accounts_get_password(0, ref randpass);
            Assert(rv, PasswordManagerStatus.NoPermission);

            // Reopen with old passphrase

            output("Unlock vault with old passphrase");
            rv = mgr.vault_unlock(mpass_old);
            Assert(rv, PasswordManagerStatus.PasswordIncorrect);

            output("Unlock vault with new passphrase");
            rv = mgr.vault_unlock(mpass_new);
            Assert(rv, PasswordManagerStatus.OK);

            output("Read accounts");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.OK);
            output(String.Format("{0} accounts", count));
            Assert((int)count, 4);

            for (ushort i = 0; i < count; ++i)
            {
                output(String.Format("Account {0}:", i));
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("    Name = {0}", SStoString(name)));
                output(String.Format("   Login = {0}", SStoString(login)));
                output(String.Format("     URL = {0}", SStoString(url)));

                rv = mgr.accounts_get_password(i, ref accountpass);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("Password = {0}", SStoString(accountpass)));
            }

            mgr.vault_lock();

            Restore();

            return true;
        }

        //----------------------------------------------------------------------
        // Vault creation tests
        //----------------------------------------------------------------------

        public bool RunNewVault ()
        {
            string path;
            int rv;
            SecureString mpass;
            SecureString acctpass = new SecureString();
            SecureString name, login, url, randpass;
            string mpass_st = "12345@#$%asdfg";
            string name_st = "IRC";
            string login_st = "jellybean";
            string url_st = "n/a";
            uint count = 0;
            uint i = 0;

            Banner("NEW VAULT TESTS");

            mpass = StoSecureString(mpass_st);
            name = StoSecureString(name_st);
            login = StoSecureString(login_st);
            url = StoSecureString(url_st);
            randpass = new SecureString();
           
            path= setup.VaultPath("test1");
            if (File.Exists(path))
            {
                output(String.Format("Deleting test vault {0}", path));
                File.Delete(path);
            }

            // Create a new vault
            output(String.Format("Creating new test vault {0}", path));
            rv= mgr.vault_create(path);
            Assert(rv, PasswordManagerStatus.OK);

            output("Unlock before creating a password");
            rv = mgr.vault_unlock(mpass);
            Assert(rv, PasswordManagerStatus.Invalid);

            // Randomly generate a password
            output("Random password");
            rv = mgr.generate_password(24, PasswordFlag.Numerals | PasswordFlag.LowerCase, ref randpass);
            Assert(rv, PasswordManagerStatus.OK);

            output("Add account before creating password");
            rv = mgr.accounts_set_info(3, name, login, url);
            Assert(rv, PasswordManagerStatus.Invalid);

            // Create password

            output("Set master password");
            rv = mgr.set_master_password(mpass, mpass);
            Assert(rv, PasswordManagerStatus.OK);

            // Get account information 

            output("Get number of accounts");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.OK);
            output(String.Format("Found {0} accounts", count));
            Assert((int)count, 0);

            output("Set/add info at account index 3");
            rv = mgr.accounts_set_info(3, name, login, url);
            Assert(rv, PasswordManagerStatus.OK);

            output("Get number of accounts");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.OK);
            output(String.Format("Found {0} accounts", count));
            Assert((int)count, 4);

            for (i = 0; i < count; ++i)
            {
                output(String.Format("Account {0}:", i));
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("    Name = {0}", SStoString(name)));
                output(String.Format("   Login = {0}", SStoString(login)));
                output(String.Format("     URL = {0}", SStoString(url)));

                rv = mgr.accounts_get_password(i, ref acctpass);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("Password = {0}", SStoString(acctpass)));
            }

            // Now lock the vault and reopen. This should compress us down to 1 account.

            output("Locking vault");
            mgr.vault_lock();
            output("Unlocking vault");
            rv= mgr.vault_unlock(mpass);
            Assert(rv, PasswordManagerStatus.OK);

            output("Get number of accounts");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.OK);
            output(String.Format("Found {0} accounts", count));
            Assert((int)count, 1);

            for (i = 0; i < count; ++i)
            {
                output(String.Format("Account {0}:", i));
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("    Name = {0}", SStoString(name)));
                output(String.Format("   Login = {0}", SStoString(login)));
                output(String.Format("     URL = {0}", SStoString(url)));

                rv = mgr.accounts_get_password(i, ref acctpass);
                Assert(rv, PasswordManagerStatus.OK);
                output(String.Format("Password = {0}", SStoString(acctpass)));
            }

            return true;
        }



    }
}
