<?php declare(strict_types=1);

namespace Tine\SDDL_Parser;

class GUID
{
    public function __construct(
        protected int $data1,
        protected int $data2,
        protected int $data3,
        protected array $data4
    ) {
        assert($data1 >= 0 && $data1 < (1 << 32));
        assert($data2 >= 0 && $data2 < (1 << 16));
        assert($data3 >= 0 && $data3 < (1 << 16));
        assert(count($data4) === 8 && array_reduce($data4, fn($carry, $val) => $carry && $val >= 0 && $val < 256, true));
    }

    public function getBytes(): string
    {
        return pack('VvvC8', $this->data1, $this->data2, $this->data3, ...$this->data4);
    }

    public function getStringForm(): string
    {
        return strtoupper(sprintf('{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}', $this->data1, $this->data2, $this->data3, ...$this->data4));
    }

    public static function fromBytes(string $data, int $offset): self
    {
        return new GUID(unpack('V', $data, $offset)[1], unpack('v', $data, $offset + 4)[1], unpack('v', $data, $offset + 6)[1], array_values(unpack('C8', $data, $offset + 8)));
    }

    public static function fromString(string $str): self
    {
        if (!preg_match('/^\{([0-9A-F]{8})-([0-9A-F]{4})-([0-9A-F]{4})-([0-9A-F]{2})([0-9A-F]{2})-([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})$/', strtoupper($str), $matches)) {
            throw new ParserException('invalid GUID: ' . $str);
        }
        return new GUID(
            intval($matches[1], 16),
            intval($matches[2], 16),
            intval($matches[3], 16),
            [
                intval($matches[4], 16),
                intval($matches[5], 16),
                intval($matches[6], 16),
                intval($matches[7], 16),
                intval($matches[8], 16),
                intval($matches[9], 16),
                intval($matches[10], 16),
                intval($matches[11], 16),
            ]
        );
    }

    public const CHANGE_PASSWORD_GUID = '{AB721A53-1E2F-11D0-9819-00AA0040529B}';
}