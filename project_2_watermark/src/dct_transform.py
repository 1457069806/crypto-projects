import numpy as np
from scipy.fftpack import dct, idct

def dct_1d(signal):
    """一维DCT变换"""
    return dct(signal, norm='ortho')

def idct_1d(signal):
    """一维逆DCT变换"""
    return idct(signal, norm='ortho')

def dct_2d(block):
    """二维DCT变换"""
    return dct(dct(block.T, norm='ortho').T, norm='ortho')

def idct_2d(block):
    """二维逆DCT变换"""
    return idct(idct(block.T, norm='ortho').T, norm='ortho')

def generate_dct_matrix(n):
    """生成n×n DCT矩阵"""
    matrix = np.zeros((n, n))
    for i in range(n):
        for j in range(n):
            if i == 0:
                matrix[i, j] = 1 / np.sqrt(n)
            else:
                matrix[i, j] = np.sqrt(2 / n) * np.cos((2*j + 1)*i*np.pi / (2*n))
    return matrix
