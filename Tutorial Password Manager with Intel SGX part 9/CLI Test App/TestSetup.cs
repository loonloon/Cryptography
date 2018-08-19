using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security;


namespace CLI_Test_App
{
    class TestSetup
    {
        private string UserDocDir;
        public string UserTestDir { get; private set; }

        public TestSetup()
        {
            UserDocDir = Environment.GetFolderPath(Environment.SpecialFolder.Personal);
            UserTestDir = UserDocDir;
            Console.OutputEncoding = System.Text.Encoding.Unicode;
            // Or change it to somewhere else if you prefer
            //UserTestDir = String.Format("{0}\\CLI PW Testing", UserDocDir);
        }

        public string VaultPath(string filename)
        {
            return string.Format("{0}\\{1}.vlt", UserTestDir, filename);
        }
    }
}
