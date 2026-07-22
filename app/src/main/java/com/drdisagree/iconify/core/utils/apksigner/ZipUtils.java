package com.drdisagree.iconify.core.utils.apksigner;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Assorted ZIP format helpers.
 *
 * <p>NOTE: Most helper methods operating on {@code ByteBuffer} instances expect that the byte
 * order of these buffers is little-endian.</p>
 *
 * <p>Source: <a href="https://github.com/topjohnwu/Magisk/blob/master/app/src/main/java/com/topjohnwu/magisk/signing/ZipUtils.java">...</a></p>
 *
 * <p>The inner scan loop ({@link #nativeFindEocd}) is implemented in C (NDK) for speed.</p>
 */
public abstract class ZipUtils {

    private static final int ZIP_EOCD_REC_MIN_SIZE = 22;
    private static final int ZIP_EOCD_REC_SIG = 0x06054b50;
    private static final int ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET = 12;
    private static final int ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16;
    private static final int ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET = 20;

    private static final int ZIP64_EOCD_LOCATOR_SIZE = 20;
    private static final int ZIP64_EOCD_LOCATOR_SIG = 0x07064b50;

    private static final int UINT16_MAX_VALUE = 0xffff;

    static {
        System.loadLibrary("iconify-native");
    }

    private ZipUtils() {
    }

    /**
     * Returns the position at which ZIP End of Central Directory record starts in the provided
     * buffer or {@code -1} if the record is not present.
     *
     * <p>NOTE: Byte order of {@code zipContents} must be little-endian.
     */
    public static int findZipEndOfCentralDirectoryRecord(ByteBuffer zipContents) {
        assertByteOrderLittleEndian(zipContents);

        int capacity = zipContents.capacity();
        if (capacity < ZIP_EOCD_REC_MIN_SIZE) {
            return -1;
        }

        // Extract raw bytes without modifying the buffer's position/limit.
        byte[] arr;
        if (zipContents.hasArray()) {
            arr = zipContents.array();
        } else {
            // Direct (off-heap) buffer — copy to a heap array for the native call.
            ByteBuffer dup = zipContents.duplicate();
            dup.position(0).limit(capacity);
            arr = new byte[capacity];
            dup.get(arr);
        }

        return nativeFindEocd(arr, capacity);
    }

    /**
     * Returns {@code true} if the provided buffer contains a ZIP64 End of Central Directory
     * Locator.
     *
     * <p>NOTE: Byte order of {@code zipContents} must be little-endian.
     */
    public static boolean isZip64EndOfCentralDirectoryLocatorPresent(ByteBuffer zipContents, int zipEndOfCentralDirectoryPosition) {
        assertByteOrderLittleEndian(zipContents);

        // ZIP64 End of Central Directory Locator immediately precedes the ZIP End of Central
        // Directory Record.

        int locatorPosition = zipEndOfCentralDirectoryPosition - ZIP64_EOCD_LOCATOR_SIZE;
        if (locatorPosition < 0) {
            return false;
        }

        return zipContents.getInt(locatorPosition) == ZIP64_EOCD_LOCATOR_SIG;
    }

    /**
     * Returns the offset of the start of the ZIP Central Directory in the archive.
     *
     * <p>NOTE: Byte order of {@code zipEndOfCentralDirectory} must be little-endian.
     */
    public static long getZipEocdCentralDirectoryOffset(ByteBuffer zipEndOfCentralDirectory) {
        assertByteOrderLittleEndian(zipEndOfCentralDirectory);
        return getUnsignedInt32(zipEndOfCentralDirectory, zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET);
    }

    /**
     * Sets the offset of the start of the ZIP Central Directory in the archive.
     *
     * <p>NOTE: Byte order of {@code zipEndOfCentralDirectory} must be little-endian.
     */
    public static void setZipEocdCentralDirectoryOffset(ByteBuffer zipEndOfCentralDirectory, long offset) {
        assertByteOrderLittleEndian(zipEndOfCentralDirectory);
        setUnsignedInt32(zipEndOfCentralDirectory, zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET, offset);
    }

    /**
     * Returns the size (in bytes) of the ZIP Central Directory.
     *
     * <p>NOTE: Byte order of {@code zipEndOfCentralDirectory} must be little-endian.
     */
    public static long getZipEocdCentralDirectorySizeBytes(ByteBuffer zipEndOfCentralDirectory) {
        assertByteOrderLittleEndian(zipEndOfCentralDirectory);
        return getUnsignedInt32(zipEndOfCentralDirectory, zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET);
    }

    private static void assertByteOrderLittleEndian(ByteBuffer buffer) {
        if (buffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("ByteBuffer byte order must be little endian");
        }
    }

    private static int getUnsignedInt16(ByteBuffer buffer, int offset) {
        return buffer.getShort(offset) & 0xffff;
    }

    private static long getUnsignedInt32(ByteBuffer buffer, int offset) {
        return buffer.getInt(offset) & 0xffffffffL;
    }

    private static void setUnsignedInt32(ByteBuffer buffer, int offset, long value) {
        if ((value < 0) || (value > 0xffffffffL)) {
            throw new IllegalArgumentException("uint32 value of out range: " + value);
        }
        buffer.putInt(buffer.position() + offset, (int) value);
    }

    // ── Native methods ────────────────────────────────────────────────────────

    /**
     * Native (C) implementation of the backwards EOCD-signature scan.
     *
     * @param data  raw bytes of the ZIP archive
     * @param size  number of bytes to consider (== {@code data.length})
     * @return offset of the EOCD record, or -1
     */
    private static native int nativeFindEocd(byte[] data, int size);
}
