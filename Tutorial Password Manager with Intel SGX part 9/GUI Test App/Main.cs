using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using PasswordManagerTest;

namespace GUI_Test_App
{
    public partial class formMain : Form
    {
        TestSetup setup;
        FeatureSupport sgxfeature;

        public formMain()
        {
            sgxfeature = new FeatureSupport();
            setup = new TestSetup();

            InitializeComponent();

            if (sgxfeature.is_enabled() == 1)
            {
                sGXCodeBranchMenuItem.Checked = true;
                sGXCodeBranchMenuItem.Enabled = true;
            }
            setup.setOutputCallback(outputResults);            
        }

        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void setWorkingDirectoryToolStripMenuItem_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog dlg= new FolderBrowserDialog();
            dlg.SelectedPath = setup.getTestFolder();

            if ( dlg.ShowDialog() == DialogResult.OK )
            {
                setup.setTestFolder(dlg.SelectedPath);
            }
        }

        private void outputResults (string text, bool newline)
        {
            // Only scroll every 5 lines for sanity

            
            textBoxOutput.Update();
            if (newline) textBoxOutput.AppendText(text + Environment.NewLine);
            else textBoxOutput.AppendText(text);
           
        }

        private void buttonRun_Click(object sender, EventArgs e)
        {
            // Set our SGX support flag before creating the test suite object

            if (sGXCodeBranchMenuItem.Enabled && sGXCodeBranchMenuItem.Checked) setup.setSGXSupport(true);
            else setup.setSGXSupport(false);

            TestSuite tests = new TestSuite(setup);
            buttonRun.Enabled = false;
            textBoxOutput.Clear();
            tests.RunAll();
            buttonRun.Enabled = true;
        }
    }
}
