using System;
using System.Collections.Generic;
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
// su dung namespace de cung cap cac lop va phuong thuc thuc hien thuat toan AES
using System.Security.Cryptography;
using System.IO;
using Microsoft.Win32;

namespace LNT_MaHoa_AES
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            string inputData = txtInputData.Text.Trim();
            string encryptionKey = txtEncryptionKey.Text.Trim();

            if (!string.IsNullOrEmpty(inputData) && !string.IsNullOrEmpty(encryptionKey))
            {
                try
                {
                    string encryptedData = AES.Encrypt(inputData, encryptionKey);
                    txtEncryptedData.Text = encryptedData;
                    MessageBox.Show("Mã hóa thành công");
                }
                catch (ArgumentNullException)
                {
                    MessageBox.Show("Lỗi: Dữ liệu hoặc khóa mã hóa không được để trống.");
                }
                catch (FormatException)
                {
                    MessageBox.Show("Lỗi: Dữ liệu không đúng định dạng.");
                }
                catch (CryptographicException)
                {
                    MessageBox.Show("Lỗi: Khóa không phù hợp với yêu cầu, vui lòng nhập lại.");
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Lỗi đặc biệt: " + ex.Message);
                }
            }
            else
            {
                MessageBox.Show("Vui lòng nhập dữ liệu muốn mã hóa hoặc khóa.");
            }
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            string inputData = txtEncryptedData_Decrypt.Text.Trim();
            string encryptionKey = txtDecryptionKey.Text.Trim();

            if (!string.IsNullOrEmpty(inputData) && !string.IsNullOrEmpty(encryptionKey))
            {
                try
                {
                    string outputData = AES.DecryptAES(inputData, encryptionKey);
                    txtDecryptedData.Text = outputData;
                    MessageBox.Show("Giải mã thành công");
                }
                catch (ArgumentNullException)
                {
                    MessageBox.Show("Lỗi: Dữ liệu hoặc khóa mã hóa không được để trống.");
                }
                catch (FormatException)
                {
                    MessageBox.Show("Lỗi: Dữ liệu có sự thay đổi, không đúng định dạng.");
                }
                catch (CryptographicException)
                {
                    MessageBox.Show("Lỗi: Khóa giải mã không đúng với khóa mã hóa, vui lòng nhập lại.");
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Lỗi đặc biệt: " + ex.Message);
                }
            }
            else
            {
                MessageBox.Show("Vui lòng nhập dữ liệu giải mã hoặc khóa.");
            }
        }

        private void RandomKey_Click(object sender, RoutedEventArgs e)
        {
            var txtKey = txtEncryptionKey.Text.Trim();
            if (String.IsNullOrEmpty(txtKey))
            {
                // Khởi tạo một mảng byte để lưu trữ khóa mã hóa
                byte[] key = new byte[16]; // 128-bit = 16 bytes

                // Sử dụng RNGCryptoServiceProvider để tạo số ngẫu nhiên
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    // Điền mảng byte với số ngẫu nhiên
                    rng.GetBytes(key);
                }

                // Chuyển đổi khóa sang dạng Base64 để hiển thị trong TextBox
                string keyBase64 = Convert.ToBase64String(key);

                // Gán giá trị khóa cho TextBox
                txtEncryptionKey.Text = keyBase64;
            }
            else
            {
                MessageBox.Show("Đã tồn tại key, không thể random !!!!!.");
            }
        }

        private void Chuyen_Click(object sender, RoutedEventArgs e)
        {
            txtEncryptedData_Decrypt.Text = txtEncryptedData.Text.Trim();
            txtDecryptionKey.Text = txtEncryptionKey.Text.Trim();
        }

        private void Xoa_Click(object sender, RoutedEventArgs e)
        {
            txtInputData.Text = "";
            txtEncryptionKey.Text = "";
            txtEncryptedData.Text = "";
            txtEncryptedData_Decrypt.Text = "";
            txtDecryptionKey.Text = "";
            txtDecryptedData.Text = "";
        }

        private void ReadFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();

            if (openFileDialog.ShowDialog() == true)
            {
                string filePath = openFileDialog.FileName;

                // Đọc nội dung của tệp tin
                string fileContent = File.ReadAllText(filePath);

                if (String.IsNullOrEmpty(fileContent))
                {
                    MessageBox.Show("File rỗng, vui lòng chọn file khác");
                }
                else
                {
                    // Hiển thị nội dung trong TextBox
                    txtInputData.Text = fileContent;
                }
            }
        }

        private void XuatFileMaHoa_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();

            if (saveFileDialog.ShowDialog() == true)
            {
                string filePath = saveFileDialog.FileName;

                // Lưu nội dung từ TextBox vào tệp tin
                File.WriteAllText(filePath, txtEncryptedData.Text);

                // Hiển thị thông báo sau khi lưu thành công
                MessageBox.Show("Tệp tin đã được lưu thành công.\nĐường dẫn: " + filePath, "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);

            }
        }

        private void NhapFileMaHoa_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();

            if (openFileDialog.ShowDialog() == true)
            {
                string filePath = openFileDialog.FileName;

                // Đọc nội dung của tệp tin
                string fileContent = File.ReadAllText(filePath);

                if (String.IsNullOrEmpty(fileContent))
                {
                    MessageBox.Show("File rỗng, vui lòng chọn file khác");
                }
                else
                {
                    // Hiển thị nội dung trong TextBox
                    txtEncryptedData_Decrypt.Text = fileContent;
                }
            }
        }

        private void XuatFileKhoa_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();

            if (saveFileDialog.ShowDialog() == true)
            {
                string filePath = saveFileDialog.FileName;

                // Lưu nội dung từ TextBox vào tệp tin
                File.WriteAllText(filePath, txtEncryptionKey.Text);

                // Hiển thị thông báo sau khi lưu thành công
                MessageBox.Show("Tệp tin đã được lưu thành công.\nĐường dẫn: " + filePath, "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);

            }
        }

        private void NhapFileKhoa_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();

            if (openFileDialog.ShowDialog() == true)
            {
                string filePath = openFileDialog.FileName;

                // Đọc nội dung của tệp tin
                string fileContent = File.ReadAllText(filePath);

                if (String.IsNullOrEmpty(fileContent))
                {
                    MessageBox.Show("File rỗng, vui lòng chọn file khác");
                }
                else
                {
                    // Hiển thị nội dung trong TextBox
                    txtDecryptionKey.Text = fileContent;
                }
            }
        }
    }
}
