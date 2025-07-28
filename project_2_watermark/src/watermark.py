import numpy as np
from .dct_transform import dct_2d, idct_2d
from .utils import text_to_binary, binary_to_text, normalize_image


class DCTWatermark:
    def __init__(self, alpha=0.1, block_size=8, coeff_pos=(2, 2), q=10):
        """
        初始化水印处理器

        参数:
            alpha: 嵌入强度，值越大水印越鲁棒但图像质量可能下降
            block_size: DCT变换的块大小，通常为8x8
            coeff_pos: 用于嵌入水印的DCT系数位置(行,列)
            q: 量化步长
        """
        self.alpha = alpha
        self.block_size = block_size
        self.coeff_pos = coeff_pos  # 选择中频系数位置
        self.q = q

        # 验证参数有效性
        if self.block_size <= 0:
            raise ValueError("块大小必须为正数")
        if self.coeff_pos[0] < 0 or self.coeff_pos[0] >= self.block_size:
            raise ValueError(f"系数行位置必须在0到{self.block_size - 1}之间")
        if self.coeff_pos[1] < 0 or self.coeff_pos[1] >= self.block_size:
            raise ValueError(f"系数列位置必须在0到{self.block_size - 1}之间")

    def _preprocess_image(self, image, is_gray=False):
        """预处理图像：根据需要转换为灰度图"""
        if is_gray:
            # 如果是彩色图像，转换为灰度图
            if len(image.shape) == 3:
                # 使用 luminance 转换公式: Y = 0.299*R + 0.587*G + 0.114*B
                gray_image = 0.299 * image[:, :, 0] + 0.587 * image[:, :, 1] + 0.114 * image[:, :, 2]
                return gray_image.astype(np.float32)
            else:
                return image.astype(np.float32)
        else:
            return image.astype(np.float32)

    def embed(self, carrier_image, watermark_text):
        """
        将水印嵌入到载体图像中

        参数:
            carrier_image: 载体图像的numpy数组 (RGB或灰度图)
            watermark_text: 要嵌入的文本水印

        返回:
            含水印的图像 (numpy数组)，保持与原始图像相同的尺寸和通道数
        """
        if carrier_image is None:
            raise ValueError("载体图像不能为空")

        # 保存原始图像的形状信息（用于恢复）
        original_shape = carrier_image.shape
        is_color = len(original_shape) == 3 and original_shape[-1] == 3

        # 预处理为灰度图进行水印处理
        gray_image = self._preprocess_image(carrier_image, is_gray=True)
        height, width = gray_image.shape

        # 将水印文本转换为二进制
        watermark_bits = text_to_binary(watermark_text)
        if not watermark_bits:
            raise ValueError("水印文本不能为空")

        watermark_length = len(watermark_bits)
        bit_index = 0

        # 创建图像副本以避免修改原始图像
        watermarked_gray = gray_image.copy()

        # 遍历图像块并嵌入水印
        for i in range(0, height, self.block_size):
            for j in range(0, width, self.block_size):
                # 计算块的结束坐标，处理边界情况
                block_end_i = min(i + self.block_size, height)
                block_end_j = min(j + self.block_size, width)

                # 只有完整的块才用于嵌入水印
                if block_end_i - i != self.block_size or block_end_j - j != self.block_size:
                    continue

                # 提取当前块并进行DCT变换
                block = gray_image[i:block_end_i, j:block_end_j]
                dct_block = dct_2d(block)

                # 嵌入水印比特
                if bit_index < watermark_length:
                    bit = int(watermark_bits[bit_index])
                    u, v = self.coeff_pos

                    # 应用水印嵌入公式
                    dct_block[u, v] += self.alpha * self.q * (bit - 0.5)
                    bit_index += 1

                # 逆DCT变换并将块放回图像
                idct_block = idct_2d(dct_block)
                watermarked_gray[i:block_end_i, j:block_end_j] = idct_block

        # 如果水印没有完全嵌入，发出警告
        if bit_index < watermark_length:
            print(f"警告: 图像太小，只能嵌入{bit_index}位水印，原始水印长度为{watermark_length}位")

        # 归一化灰度图结果
        normalized_gray = normalize_image(watermarked_gray)

        # 恢复为原始图像的通道数
        if is_color:
            # 将灰度图转换回3通道（复制灰度值到每个通道）
            watermarked_image = np.stack([normalized_gray, normalized_gray, normalized_gray], axis=-1)
            # 确保数据类型正确
            watermarked_image = watermarked_image.astype(carrier_image.dtype)
            return watermarked_image
        else:
            return normalized_gray.astype(carrier_image.dtype)

    def extract(self, original_image, watermarked_image, watermark_length):
        """
        从含水印图像中提取水印

        参数:
            original_image: 原始载体图像 (用于非盲提取)
            watermarked_image: 含水印的图像
            watermark_length: 原始水印文本的长度（字符数）

        返回:
            提取的水印文本
        """
        if original_image is None or watermarked_image is None:
            raise ValueError("原始图像和含水印图像都不能为空")

        if original_image.shape != watermarked_image.shape:
            raise ValueError("原始图像和含水印图像必须具有相同的尺寸")

        # 预处理为灰度图进行水印提取
        orig_gray = self._preprocess_image(original_image, is_gray=True)
        watermarked_gray = self._preprocess_image(watermarked_image, is_gray=True)

        height, width = orig_gray.shape
        total_bits = watermark_length * 8  # 每个字符8位
        extracted_bits = []

        # 遍历图像块并提取水印
        for i in range(0, height, self.block_size):
            for j in range(0, width, self.block_size):
                # 计算块的结束坐标
                block_end_i = min(i + self.block_size, height)
                block_end_j = min(j + self.block_size, width)

                # 只处理完整的块
                if block_end_i - i != self.block_size or block_end_j - j != self.block_size:
                    continue

                # 对原始图像块和含水印图像块进行DCT变换
                orig_block = orig_gray[i:block_end_i, j:block_end_j]
                watermarked_block = watermarked_gray[i:block_end_i, j:block_end_j]

                orig_dct = dct_2d(orig_block)
                watermarked_dct = dct_2d(watermarked_block)

                # 提取水印比特
                if len(extracted_bits) < total_bits:
                    u, v = self.coeff_pos
                    diff = watermarked_dct[u, v] - orig_dct[u, v]

                    # 根据差值判断水印比特
                    extracted_bit = '1' if diff >= 0 else '0'
                    extracted_bits.append(extracted_bit)

                # 如果已提取足够的比特，提前退出
                if len(extracted_bits) >= total_bits:
                    break
            if len(extracted_bits) >= total_bits:
                break

        # 将二进制转换为文本并返回
        return binary_to_text(''.join(extracted_bits))

    def blind_extract(self, watermarked_image, watermark_length):
        """
        盲提取水印（不需要原始图像）

        参数:
            watermarked_image: 含水印的图像
            watermark_length: 原始水印文本的长度（字符数）

        返回:
            提取的水印文本
        """
        # 对于盲提取，我们假设原始DCT系数为0（简化实现）
        # 在实际应用中，应使用更复杂的统计方法估计原始系数
        height, width = watermarked_image.shape[:2]
        dummy_original = np.zeros((height, width), dtype=np.float32)
        if len(watermarked_image.shape) == 3 and watermarked_image.shape[-1] == 3:
            dummy_original = np.stack([dummy_original, dummy_original, dummy_original], axis=-1)
        return self.extract(dummy_original, watermarked_image, watermark_length)
