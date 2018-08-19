using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security;
using System.Runtime.InteropServices;
using System.Threading;

using PasswordManager;

namespace CLI_Test_App
{
    class TestSuite {
        TestSetup setup;
        PasswordManagerCore mgr;
        String working_vault;

        public TestSuite ()
        {
            mgr = new PasswordManagerCore();
            setup = new TestSetup();
        }

        public bool RunAll()
        {
           try {
                this.Initialize();
                this.RunNewVault();
                this.RunExistingVault();
           }
           catch {                
                return false;
           }

           Console.WriteLine("Sleeping for 15 seconds to let clipboard timers finish...");
           Thread.Sleep(15000);
           return true;
        }

        public void Banner (string hdr)
        {
            Console.WriteLine("=========================================================");
            Console.WriteLine(hdr);
            Console.WriteLine("=========================================================");
        }

        public bool Initialize()
        {
            if (!Directory.Exists(setup.UserTestDir))
            {
                Console.WriteLine("Creating test directory {0}", setup.UserTestDir);
                try
                {
                    Directory.CreateDirectory(setup.UserTestDir);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error: {0}", e.ToString());
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
            Console.WriteLine("Backing up original vault file {0} to {1}", path, orig);
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

                Console.WriteLine("Copying modified vault to {0}", mod);
                Console.WriteLine("Restoring original vault file from {0} to {1}", orig, path);
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
            Console.Write("    Expected {0}, received {1}...>>> ", expected, received);
            AssertResult(expected == received);
        }
        void Assert (int received, int expected)
        {
            Console.Write("    Expected {0}, received {1}...>>> ", expected, received);
            AssertResult(expected == received);
        }

        void AssertResult (bool result)
        {
            if (!result)
            {
                Console.WriteLine("FAIL <<<");
                Restore();
                throw new System.ArgumentException("Test failure");
            }
            Console.WriteLine("PASS <<<");
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
            Console.WriteLine("Checking for reference vault {0}", path);
            Assert(File.Exists(path), true);

            // Make a copy of our original vault file which we can restore later.
            Backup(path);

            Console.WriteLine("Create new vault on top of existing vault {0}", path);
            rv = mgr.vault_create(path);
            Assert(rv, PasswordManagerStatus.Exists);

            Console.WriteLine("Opening vault {0}", path);
            rv = mgr.vault_open(path);
            Assert(rv, PasswordManagerStatus.OK);

            Console.WriteLine("Generate password");
            rv = mgr.generate_password(16, PasswordFlag.UpperCase | PasswordFlag.LowerCase | PasswordFlag.Numerals, ref randpass);
            Assert(rv, PasswordManagerStatus.OK);
            Console.WriteLine("Password: {0}", SStoString(randpass));

            Console.WriteLine("Set master password");
            rv = mgr.set_master_password(randpass);
            Assert(rv, PasswordManagerStatus.NoPermission);

            Console.WriteLine("Change master password");
            rv = mgr.change_master_password(new SecureString(), randpass);
            Assert(rv, PasswordManagerStatus.NoPermission);

            Console.WriteLine("Read accounts without unlocking");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.NoPermission);

            Console.WriteLine("Read account password without unlocking");
            rv = mgr.accounts_get_password(0, ref randpass);
            Assert(rv, PasswordManagerStatus.NoPermission);

            Console.WriteLine("Read account without unlocking");
            rv = mgr.accounts_get_info(0, ref name, ref login, ref url);
            Assert(rv, PasswordManagerStatus.NoPermission);

            Console.WriteLine("Update account without unlocking");
            rv = mgr.accounts_set_info(0, name, login, url);
            Assert(rv, PasswordManagerStatus.NoPermission);

            Console.WriteLine("Unlock with wrong password");
            rv = mgr.vault_unlock(randpass);
            Assert(rv, PasswordManagerStatus.PasswordIncorrect);

            Console.WriteLine("Unlock vault");
            rv = mgr.vault_unlock(mpass_old);
            Assert(rv, PasswordManagerStatus.OK);

            Console.WriteLine("Set master password");
            rv = mgr.set_master_password(randpass);
            Assert(rv, PasswordManagerStatus.Invalid);

            Console.WriteLine("Change master password to itself");
            rv = mgr.change_master_password(mpass_old, mpass_old);
            Assert(rv, PasswordManagerStatus.NoChange);

            Console.WriteLine("Read accounts");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.OK);
            Console.WriteLine("{0} accounts", count);
            Assert((int)count, 3);

            for (uint i = 0; i < count; ++i)
            {
                Console.WriteLine("Account {0}:", i);
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("    Name = '{0}'", SStoString(name));
                Console.WriteLine("   Login = '{0}'", SStoString(login));
                Console.WriteLine("     URL = '{0}'", SStoString(url));

                rv = mgr.accounts_get_password(i, ref accountpass);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("Password = '{0}'", SStoString(accountpass));
            }

            // Chenge all the account passwords to random ones

            for (ushort i = 0; i < count; ++i)
            {
                Console.WriteLine("Generating new password for account {0}", i);
                rv = mgr.generate_password(16, PasswordFlag.All, ref randpass);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("Password {0}: '{1}'", i, SStoString(randpass));

                Console.WriteLine("Changing account password for account {0}", i);
                rv = mgr.accounts_set_password(i, randpass);
                Assert(rv, PasswordManagerStatus.OK);

                Console.WriteLine("Getting new password for account {0}", i);
                rv = mgr.accounts_get_password(i, ref accountpass);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("New password = '{0}'", SStoString(accountpass));
                Console.WriteLine("Comparing generated password '{0}' to assigned password '{1}'", SStoString(randpass), SStoString(accountpass));
                Assert(SecureStringEqual(randpass, accountpass), true);
            }

            // Try account that doesn't exist...

            Console.WriteLine("Fetching undefined account 5:", 5);
            rv = mgr.accounts_get_info(5, ref name, ref login, ref url);
            Assert(rv, PasswordManagerStatus.OK);
            Console.WriteLine("    Name = {0}", SStoString(name));
            Console.WriteLine("   Login = {0}", SStoString(login));
            Console.WriteLine("     URL = {0}", SStoString(url));

            Console.WriteLine("Fetch password for account 5 to clipboard");
            rv = mgr.accounts_get_password(5, ref accountpass);
            Assert(rv, PasswordManagerStatus.OK);
            Console.WriteLine("Password = {0}", SStoString(accountpass));
            Console.WriteLine("Comparing empty password to undefined account password {0}", SStoString(accountpass));
            Assert(SecureStringEqual(emptypass, accountpass), true);

            Console.WriteLine("Copy password for account 5 to clipboard");
            rv = mgr.accounts_password_to_clipboard(5);
            Assert(rv, PasswordManagerStatus.OK);

            // ...and is out of range
            Console.WriteLine("Copy password for account 105 to clipboard");
            rv = mgr.accounts_password_to_clipboard(105);
            Assert(rv, PasswordManagerStatus.Range);

            Console.WriteLine("Copy password for account 1 to clipboard");
            rv = mgr.accounts_password_to_clipboard(1);
            Assert(rv, PasswordManagerStatus.OK);

            Console.WriteLine("Copy password for account 2 to clipboard");
            rv = mgr.accounts_password_to_clipboard(2);
            Assert(rv, PasswordManagerStatus.OK);

            // Set account information

            {
                // Replace existing
                UInt32 i = 2;

                SecureString newname = StoSecureString("AOL");
                SecureString newlogin = StoSecureString("aoluser");
                SecureString newurl = StoSecureString("http://aol.com/");
                Console.WriteLine("Write new account information for account {0}", i);
                rv = mgr.accounts_set_info(i, newname, newlogin, newurl);
                Assert(rv, PasswordManagerStatus.OK);

                Console.WriteLine("Get new account information for account {0}:", i);
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("    Name = {0} (should be {1})", SStoString(name), SStoString(newname));
                Assert(SecureStringEqual(name, newname), true);
                Console.WriteLine("   Login = {0} (should be {1})", SStoString(login), SStoString(newlogin));
                Assert(SecureStringEqual(login, newlogin), true);
                Console.WriteLine("     URL = {0} (should be {1})", SStoString(url), SStoString(newurl));
                Assert(SecureStringEqual(url, newurl), true);
            }

            {
                // Set undefined with partial data
                UInt32 i = 6;

                SecureString newname = StoSecureString("Non-ASCII chars «ταБЬℓσ»");
                SecureString newlogin = StoSecureString("");
                SecureString newurl = StoSecureString("http://unicodetest.net/");
                Console.WriteLine("Write new account information for account {0}", i);
                rv = mgr.accounts_set_info(i, newname, newlogin, newurl);
                Assert(rv, PasswordManagerStatus.OK);

                Console.WriteLine("Get new account information for account {0}:", i);
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("    Name = {0} (should be {1})", SStoString(name), SStoString(newname));
                Assert(SecureStringEqual(name, newname), true);
                Console.WriteLine("   Login = {0} (should be {1})", SStoString(login), SStoString(newlogin));
                Assert(SecureStringEqual(login, newlogin), true);
                Console.WriteLine("     URL = {0} (should be {1})", SStoString(url), SStoString(newurl));
                Assert(SecureStringEqual(url, newurl), true);
            }

            // Change the master password

            Console.WriteLine("Change master password");
            rv = mgr.change_master_password(mpass_old, mpass_new);
            Assert(rv, PasswordManagerStatus.OK);

            // Lock the vault

            Console.WriteLine("Lock the vault");
            mgr.vault_lock();
            Assert(rv, PasswordManagerStatus.OK);

            // Now try and read something back.

            Console.WriteLine("Read accounts  after locking");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.NoPermission);

            Console.WriteLine("Read account password after locking");
            rv = mgr.accounts_get_password(0, ref randpass);
            Assert(rv, PasswordManagerStatus.NoPermission);

            // Reopen with old passphrase

            Console.WriteLine("Unlock vault with old passphrase");
            rv = mgr.vault_unlock(mpass_old);
            Assert(rv, PasswordManagerStatus.PasswordIncorrect);

            Console.WriteLine("Unlock vault with new passphrase");
            rv = mgr.vault_unlock(mpass_new);
            Assert(rv, PasswordManagerStatus.OK);

            Console.WriteLine("Read accounts");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.OK);
            Console.WriteLine("{0} accounts", count);
            Assert((int)count, 4);

            for (ushort i = 0; i < count; ++i)
            {
                Console.WriteLine("Account {0}:", i);
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("    Name = {0}", SStoString(name));
                Console.WriteLine("   Login = {0}", SStoString(login));
                Console.WriteLine("     URL = {0}", SStoString(url));

                rv = mgr.accounts_get_password(i, ref accountpass);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("Password = {0}", SStoString(accountpass));
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
                Console.WriteLine("Deleting test vault {0}", path);
                File.Delete(path);
            }

            // Create a new vault
            Console.WriteLine("Creating new test vault {0}", path);
            rv= mgr.vault_create(path);
            Assert(rv, PasswordManagerStatus.OK);

            Console.WriteLine("Unlock before creating a password");
            rv = mgr.vault_unlock(mpass);
            Assert(rv, PasswordManagerStatus.Invalid);

            // Randomly generate a password
            Console.WriteLine("Random password");
            rv = mgr.generate_password(24, PasswordFlag.Numerals | PasswordFlag.LowerCase, ref randpass);
            Assert(rv, PasswordManagerStatus.OK);

            Console.WriteLine("Add account before creating password");
            rv = mgr.accounts_set_info(3, name, login, url);
            Assert(rv, PasswordManagerStatus.Invalid);

            // Create password

            Console.WriteLine("Set master password");
            rv = mgr.set_master_password(mpass);
            Assert(rv, PasswordManagerStatus.OK);

            // Get account information 

            Console.WriteLine("Get number of accounts");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.OK);
            Console.WriteLine("Found {0} accounts", count);
            Assert((int)count, 0);

            Console.WriteLine("Set/add info at account index 3");
            rv = mgr.accounts_set_info(3, name, login, url);
            Assert(rv, PasswordManagerStatus.OK);

            Console.WriteLine("Get number of accounts");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.OK);
            Console.WriteLine("Found {0} accounts", count);
            Assert((int)count, 4);

            for (i = 0; i < count; ++i)
            {
                Console.WriteLine("Account {0}:", i);
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("    Name = {0}", SStoString(name));
                Console.WriteLine("   Login = {0}", SStoString(login));
                Console.WriteLine("     URL = {0}", SStoString(url));

                rv = mgr.accounts_get_password(i, ref acctpass);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("Password = {0}", SStoString(acctpass));
            }

            // Now lock the vault and reopen. This should compress us down to 1 account.

            Console.WriteLine("Locking vault");
            mgr.vault_lock();
            Console.WriteLine("Unlocking vault");
            rv= mgr.vault_unlock(mpass);
            Assert(rv, PasswordManagerStatus.OK);

            Console.WriteLine("Get number of accounts");
            rv = mgr.accounts_get_count(ref count);
            Assert(rv, PasswordManagerStatus.OK);
            Console.WriteLine("Found {0} accounts", count);
            Assert((int)count, 1);

            for (i = 0; i < count; ++i)
            {
                Console.WriteLine("Account {0}:", i);
                rv = mgr.accounts_get_info(i, ref name, ref login, ref url);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("    Name = {0}", SStoString(name));
                Console.WriteLine("   Login = {0}", SStoString(login));
                Console.WriteLine("     URL = {0}", SStoString(url));

                rv = mgr.accounts_get_password(i, ref acctpass);
                Assert(rv, PasswordManagerStatus.OK);
                Console.WriteLine("Password = {0}", SStoString(acctpass));
            }

            return true;
        }



    }
}
