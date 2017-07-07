using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;
using TOTP.Core;

namespace TOTP.Demo
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        public MainWindow()
        {
            InitializeComponent();
            Key = "testkey";
            Step = 30;

            var timer = new DispatcherTimer();
            timer.Interval = TimeSpan.FromMilliseconds(500);
            timer.Tick += (s, e) => Seconds = TOTP.Core.TOTP.GetEffectiveSeconds(Step);
            timer.IsEnabled = true;
            DataContext = this;
        }

        #region Implementation of INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;
        private void OnPropertyChanged(string propertyName)
        {
            if (PropertyChanged != null)
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
        }
        #endregion

        #region Property
        string key;
        public string Key
        {
            get { return key; }
            set
            {
                key = value;
                OnPropertyChanged("Key");
                CalculateTOTP();
            }
        }

        int step;
        public int Step
        {
            get { return step; }
            set
            {
                step = value;
                OnPropertyChanged("Step");
                CalculateTOTP();
            }
        }

        int seconds;
        public int Seconds
        {
            get { return seconds; }
            private set
            {
                seconds = value;
                OnPropertyChanged("Seconds");
                if (seconds == Step)
                    CalculateTOTP();

            }
        }

        string totp;
        public string Totp
        {
            get { return totp; }
            private set
            {
                totp = value;
                OnPropertyChanged("Totp");
            }
        }
        #endregion

        private void CalculateTOTP()
        {
            if (Step == 0)
                return;
            byte[] keyBytes = Encoding.ASCII.GetBytes(Key);
            Totp = TOTP.Core.TOTP.GenerateTOTP(keyBytes, Step).ToString();
        }
    }
}
