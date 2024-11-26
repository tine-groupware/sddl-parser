<?php declare(strict_types=1);

namespace Tine\SDDL_Parser\ACE;

use Tine\SDDL_Parser\ACE;
use Tine\SDDL_Parser\ParserException;
use Tine\SDDL_Parser\SID;

class AccessMask extends ACE
{
    public function __construct(string $binaryForm, int $flags, int $type,
        protected int $accessMask,
        protected SID $sid
    ) {
        parent::__construct($binaryForm, $flags, $type);
    }

    public function toBytes(): string
    {
        $sid = $this->sid->getBinaryForm();
        return pack('C2vV', $this->type, $this->flags, strlen($sid) + 8, $this->accessMask) . $sid;
    }

    public static function fromBytes(string $data, int $offset): self
    {
        $aceType = unpack('C', $data, $offset)[1]; // one character
        $aceFlags = unpack('C', $data, $offset + 1)[1]; // one character
        $aceSize = unpack('v', $data, $offset + 2)[1]; // little endian unsigned 16 bit

        if ($aceSize < 16) {
            throw new ParserException('AccessMask ACE size needs to be at least 16: ' . $aceSize);
        }

        $accessMask = unpack('V', $data, $offset + 4)[1]; // little endian unsigned 32 bit

        return new self(substr($data, $offset, $aceSize), $aceFlags, $aceType, $accessMask, SID::fromBytes($data, $offset + 8));
    }
}
