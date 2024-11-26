<?php declare(strict_types=1);

namespace Tine\SDDL_Parser\ACE;

use Tine\SDDL_Parser\ACE;
use Tine\SDDL_Parser\GUID;
use Tine\SDDL_Parser\ParserException;
use Tine\SDDL_Parser\SID;

class ObjectAccess extends ACE
{
    public function __construct(string $binaryForm, int $flags, int $type,
                                protected int $accessMask,
                                protected int $uniqueFlags,
                                protected ?GUID $object,
                                protected ?GUID $inheritedObject,
                                protected SID $sid
    ) {
        parent::__construct($binaryForm, $flags, $type);
    }

    public function setUniqueFlags(int $flags): self
    {
        $this->uniqueFlags = $flags;
        return $this;
    }

    public function setAccessMask(int $mask): self
    {
        $this->accessMask = $mask;
        return $this;
    }

    public function getSID(): SID
    {
        return $this->sid;
    }

    public function getObject(): ?GUID
    {
        return $this->object;
    }

    public function setInheritedObject(?GUID $guid): self
    {
        $this->inheritedObject = $guid;
        return $this;
    }

    public function setType(int $type): self
    {
        if ($type !== ACE::ACETYPE_ACCESS_ALLOWED_OBJECT && $type !== ACE::ACETYPE_ACCESS_DENIED_OBJECT) {
            throw new ParserException('type not allowed: ' . $type);
        }
        $this->type = $type;
        return $this;
    }
    public function setFlags(int $flags): self
    {
        $this->flags = $flags;
        return $this;
    }


    public function toBytes(): string
    {
        $objBytes = $this->object?->getBytes() ?? '';
        $inheritedObjBytes = $this->inheritedObject?->getBytes() ?? '';
        $sid = $this->sid->getBinaryForm();
        $len = strlen($objBytes) + strlen($inheritedObjBytes) + strlen($sid) + 12;
        return pack('C2vVV', $this->type, $this->flags, $len, $this->accessMask, $this->uniqueFlags)
            . $objBytes . $inheritedObjBytes . $sid;
    }

    public static function fromBytes(string $data, int $offset): self
    {
        $aceType = unpack('C', $data, $offset)[1]; // one character
        $aceFlags = unpack('C', $data, $offset + 1)[1]; // one character
        $aceSize = unpack('v', $data, $offset + 2)[1]; // little endian unsigned 16 bit

        if ($aceSize < 16) {
            throw new ParserException('ObjectAccess ACE size needs to be at least 16: ' . $aceSize);
        }

        $accessMask = unpack('V', $data, $offset + 4)[1]; // little endian unsigned 32 bit
        $uniqueFlags = unpack('V', $data, $offset + 8)[1]; // little endian unsigned 32 bit

        $nextOffset = $offset + 12;
        $object = null;
        if ($uniqueFlags & ACE::ACE_OBJECT_TYPE_PRESENT) {
            $object = GUID::fromBytes($data, $nextOffset);
            $nextOffset += 16;
        }
        $inheritedObject = null;
        if ($uniqueFlags & ACE::ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            $inheritedObject = GUID::fromBytes($data, $nextOffset);
            $nextOffset += 16;
        }

        return new self(substr($data, $offset, $aceSize), $aceFlags, $aceType, $accessMask, $uniqueFlags,
            $object, $inheritedObject, SID::fromBytes($data, $nextOffset));
    }
}
