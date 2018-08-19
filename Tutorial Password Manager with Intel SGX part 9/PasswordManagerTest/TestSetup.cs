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
using System.Security;

public delegate void OutputCallback(string text, bool newline= true);

namespace PasswordManagerTest
{
    public class TestSetup
    {
        private string UserDocDir;
        public string UserTestDir { get; private set; }
        private bool sgx;
        OutputCallback output;

        public TestSetup()
        {
            UserDocDir = Environment.GetFolderPath(Environment.SpecialFolder.Personal);
            UserTestDir = UserDocDir;
            Console.OutputEncoding = System.Text.Encoding.Unicode;
            sgx = false;
            output = this.OutputConsole;
            // Or change it to somewhere else if you prefer
            //UserTestDir = String.Format("{0}\\CLI PW Testing", UserDocDir);
        }

        public void setOutputCallback(OutputCallback callback)
        {
            output = callback;
        }

        public void setTestFolder(string path)
        {
            UserTestDir = path;
        }

        public void setSGXSupport (bool state)
        {
            sgx = state;
        }

        public bool getSGXSupport ()
        {
            return sgx;
        }

        public string getTestFolder ()
        {
            return UserTestDir;
        }

        public OutputCallback getOutputCallback()
        {
            return output;
        }

        public string VaultPath(string filename)
        {
            return string.Format("{0}\\{1}.vlt", UserTestDir, filename);
        }

        public void OutputConsole(string text, bool newline= true)
        {
            if (newline) { Console.WriteLine(text); }
            else { Console.Write(text); }
        }
    }
}
