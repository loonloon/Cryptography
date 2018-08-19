using Microsoft.Win32;

namespace Password_manager
{
    public class UserPrefs
    {
        private RegistryKey _key;
        private readonly string _keyname = "SOFTWARE\\Intel\\Tutorial Password Manager with Intel SGX";
        private int _lockDelay;
        public int LockDelay
        {
            get
            {
                if (_lockDelay < 0)
                {
                    return 0;
                }

                if (_lockDelay > 10)
                {
                    return 10;
                }

                return _lockDelay;
            }
            set
            {
                if (value < 0)
                {
                    _lockDelay = 0;
                }
                else if (value > 10)
                {
                    _lockDelay = 10;
                }
                else
                {
                    _lockDelay = value;
                }
            }
        }

        public const int DefLockDelay = 0;

        public UserPrefs()
        {
            _key = Registry.CurrentUser.OpenSubKey(_keyname, true);

            if (_key == null)
            {
                LockDelay = DefLockDelay;
            }
            else
            {
                LockDelay = (int)_key.GetValue("LockDelay", DefLockDelay);
            }
        }

        public void SavePrefs()
        {
            if (_key == null)
            {
                _key = Registry.CurrentUser.CreateSubKey(_keyname);

                if (_key == null)
                {
                    return;
                }
            }

            _key.SetValue("LockDelay", LockDelay, RegistryValueKind.DWord);
        }
    }
}
