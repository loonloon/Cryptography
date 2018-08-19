using System.Windows;

namespace Password_manager
{
    /// <summary>
    /// Interaction logic for OptionsDialog.xaml
    /// </summary>
    public partial class OptionsDialog : Window
    {
        private readonly UserPrefs _prefs;
        private int _lockDelay;

        public OptionsDialog(UserPrefs prefsIn)
        {
            _prefs = prefsIn;
            InitializeComponent();
            slLockDelay.Value = _prefs.LockDelay;
        }

        private void btnOK_Click(object sender, RoutedEventArgs e)
        {
            if (_lockDelay != _prefs.LockDelay)
            {
                _prefs.LockDelay = _lockDelay > 10 ? 10 : _lockDelay;
                DialogResult = true;
            }
            else
            {
                DialogResult = false;
            }

            Close();
        }

        private void btnCancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void slLockDelay_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            _lockDelay = (int)slLockDelay.Value;

            if (_lockDelay > 10)
            {
                _lockDelay = 10;
            }
        }
    }
}
