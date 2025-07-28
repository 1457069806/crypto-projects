import numpy as np
from PIL import Image, ImageFilter
import random


def jpeg_compression(image, quality=50):
    """JPEG压缩攻击"""
    # 转换为PIL图像
    pil_img = Image.fromarray(image)

    # 保存为低质量JPEG然后重新加载
    from io import BytesIO
    buffer = BytesIO()
    pil_img.save(buffer, format='JPEG', quality=quality)
    buffer.seek(0)
    attacked_img = Image.open(buffer)

    return np.array(attacked_img)


def add_gaussian_noise(image, mean=0, var=0.001):
    """高斯噪声攻击"""
    image = image.astype(np.float32)
    sigma = var ** 0.5
    gauss = np.random.normal(mean, sigma, image.shape)
    noisy_image = image + gauss
    return np.clip(noisy_image, 0, 255).astype(np.uint8)


def add_salt_pepper_noise(image, prob=0.01):
    """椒盐噪声攻击"""
    output = np.zeros(image.shape, np.uint8)
    thres = 1 - prob
    for i in range(image.shape[0]):
        for j in range(image.shape[1]):
            rdn = random.random()
            if rdn < prob:
                output[i][j] = 0  # 椒噪声
            elif rdn > thres:
                output[i][j] = 255  # 盐噪声
            else:
                output[i][j] = image[i][j]
    return output


def crop_image(image, ratio=0.1):  # 把 crop_ratio 改成 ratio，和调用处统一
    """裁剪攻击"""
    h, w = image.shape[:2]
    crop_h = int(h * ratio)
    crop_w = int(w * ratio)
    cropped = image[crop_h:, crop_w:]
    from PIL import Image
    pil_img = Image.fromarray(cropped)
    return np.array(pil_img.resize((w, h), Image.BILINEAR))


def rotate_image(image, angle=10):
    """旋转攻击"""
    pil_img = Image.fromarray(image)
    rotated = pil_img.rotate(angle)
    return np.array(rotated.resize(image.shape[:2][::-1], Image.BILINEAR))


def resize_image(image, scale=0.8):
    """缩放攻击"""
    h, w = image.shape[:2]
    new_h, new_w = int(h * scale), int(w * scale)

    pil_img = Image.fromarray(image)
    scaled = pil_img.resize((new_w, new_h), Image.BILINEAR)
    return np.array(scaled.resize((w, h), Image.BILINEAR))


def gaussian_blur(image, radius=2):
    """高斯模糊攻击"""
    pil_img = Image.fromarray(image)
    blurred = pil_img.filter(ImageFilter.GaussianBlur(radius=radius))
    return np.array(blurred)


def median_filter(image, size=3):
    """中值滤波攻击"""
    pil_img = Image.fromarray(image)
    filtered = pil_img.filter(ImageFilter.MedianFilter(size=size))
    return np.array(filtered)
