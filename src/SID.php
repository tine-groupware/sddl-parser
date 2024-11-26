<?php declare(strict_types=1);

namespace Tine\SDDL_Parser;

class SID
{
    public function __construct(
        protected string $stringForm,
        protected string $binaryForm
    ) {}

    public function getStringForm(): string
    {
        return $this->stringForm;
    }

    public function getBinaryForm(): string
    {
        return $this->binaryForm;
    }

    public function setStringForm(string $string): self
    {
        throw new ParserException('not implemented');
        //$this->stringForm = $string;
        //return $this;
    }

    public function setBinaryForm(string $string): self
    {
        $sid = self::fromBytes($string, 0);
        $this->stringForm = $sid->getStringForm();
        $this->binaryForm = $sid->getStringForm();
        return $this;
    }

    public static function fromString($str): self
    {
        return new self($sid, $str);
    }

    public static function fromBytes(string $data, int $offset): self
    {
        if (strlen($data) < $offset + 12) {
            throw new ParserException('sid parsing failed, remaining data to short');
        }
        $header = unpack('C8', $data, $offset); // 8 chars
        if ($header[1] !== 1) {
            throw new ParserException('sid byte one expected to equal 1: ' . $header[1]);
        }
        if ($header[2] < 1 || $header[2] > 15) {
            throw new ParserException('sid byte two expected to be in range 1-15: ' . $header[2]);
        }
        $sidLength = 8 + $header[2] * 4;
        if (strlen($data) < $offset + $sidLength) {
            throw new ParserException('sid parsing failed, remaining data to short');
        }
        $auth = ($header[3] << 40) | ($header[4] << 32) | ($header[5] << 24) | ($header[6] << 16) | ($header[7] << 8) | $header[8];
        $sid = 'S-1-' . $auth;
        for ($i = 0; $i < $header[2]; ++$i) {
            $subAuth = unpack('V', $data, $offset + 8 + $i * 4); // little endian unsigned 32 bit
            $sid .= '-' . $subAuth[1];
        }

        return new self($sid, substr($data, $offset, $sidLength));
    }

    public const SID_EVERYONE = 'S-1-1-0';
    public const SID_NT_AUTHORITY_SELF = 'S-1-5-10';
}