import unittest
import os
import numpy as np
from project_2_watermark.src.watermark import DCTWatermark
from project_2_watermark.src.utils import text_to_binary, binary_to_text, psnr, ber


class TestDCTWatermark(unittest.TestCase):
    """测试DCT水印算法的单元测试类"""

    def setUp(self):
        """测试前的准备工作"""
        # 创建一个512x512的测试图像（白色背景）
        self.test_image = np.ones((512, 512, 3), dtype=np.uint8) * 255
        # 创建一个灰度测试图像
        self.gray_image = np.ones((512, 512), dtype=np.uint8) * 255
        # 测试水印文本
        self.watermark_text = "Test watermark 1234567890!@#$%"
        # 创建水印处理器实例
        self.watermarker = DCTWatermark(alpha=0.15)

        # 创建临时目录
        if not os.path.exists('tests/temp'):
            os.makedirs('tests/temp')

    def tearDown(self):
        """测试后的清理工作"""
        # 可以在这里清理临时文件
        pass

    def test_text_binary_conversion(self):
        """测试文本与二进制的转换功能"""
        binary = text_to_binary(self.watermark_text)
        text = binary_to_text(binary)
        self.assertEqual(text, self.watermark_text)

    def test_embed_extract_rgb(self):
        """测试对RGB图像的水印嵌入和提取"""
        # 嵌入水印
        watermarked = self.watermarker.embed(self.test_image, self.watermark_text)

        # 提取水印
        extracted = self.watermarker.extract(self.test_image, watermarked, len(self.watermark_text))

        # 验证提取的水印是否正确
        self.assertEqual(extracted, self.watermark_text)

    def test_embed_extract_gray(self):
        """测试对灰度图像的水印嵌入和提取"""
        # 嵌入水印
        watermarked = self.watermarker.embed(self.gray_image, self.watermark_text)

        # 提取水印
        extracted = self.watermarker.extract(self.gray_image, watermarked, len(self.watermark_text))

        # 验证提取的水印是否正确
        self.assertEqual(extracted, self.watermark_text)

    def test_image_quality(self):
        """测试嵌入水印后的图像质量（PSNR）"""
        # 嵌入水印
        watermarked = self.watermarker.embed(self.test_image, self.watermark_text)

        # 转换为灰度图用于PSNR计算
        from project_2_watermark.src.utils import normalize_image
        test_gray = normalize_image(0.299 * self.test_image[:, :, 0] +
                                    0.587 * self.test_image[:, :, 1] +
                                    0.114 * self.test_image[:, :, 2])

        # 计算PSNR值，应大于30dB（人眼难以察觉差异）
        psnr_value = psnr(test_gray, watermarked)
        self.assertGreater(psnr_value, 30)

    def test_parameters_validation(self):
        """测试参数验证功能"""
        # 测试无效的块大小
        with self.assertRaises(ValueError):
            DCTWatermark(block_size=0)

        # 测试无效的系数位置
        with self.assertRaises(ValueError):
            DCTWatermark(coeff_pos=(10, 2))  # 行位置超出范围

        with self.assertRaises(ValueError):
            DCTWatermark(coeff_pos=(2, 10))  # 列位置超出范围

    def test_blind_extraction(self):
        """测试盲提取功能（不使用原始图像）"""
        # 嵌入水印
        watermarked = self.watermarker.embed(self.test_image, self.watermark_text)

        # 盲提取水印
        extracted = self.watermarker.blind_extract(watermarked, len(self.watermark_text))

        # 盲提取可能不会完全准确，但应该有较高的相似度
        original_bits = text_to_binary(self.watermark_text)
        extracted_bits = text_to_binary(extracted)
        error_rate = ber(original_bits, extracted_bits)

        # 错误率应低于20%
        self.assertLess(error_rate, 0.2)


if __name__ == '__main__':
    unittest.main()
