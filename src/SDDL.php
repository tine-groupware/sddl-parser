<?php declare(strict_types=1);

namespace Tine\SDDL_Parser;

class SDDL
{
    public static function fromBytes(string $data): self
    {
        $sddl = new self();

        $dataLen = strlen($data);
        if ($dataLen < 20) {
            throw new ParserException('data too short: ' . $dataLen);
        }
        $header = unpack('C2', $data); // two characters
        if ($header[1] !== 1) {
            throw new ParserException('first byte expected to equal 1, found: ' . $header[1]);
        }
        if ($header[2] !== 0) {
            throw new ParserException('second byte expected to equal 0, found: ' . $header[2]);
        }
        $sddl->setControllFlags(unpack('v', $data, 2)[1]); // little endian unsigned 16 bit

        $ownerOffset = unpack('V', $data, 4)[1]; // little endian unsigned 32 bit
        $groupOffset = unpack('V', $data, 8)[1]; // little endian unsigned 32 bit
        $saclOffset  = unpack('V', $data, 12)[1]; // little endian unsigned 32 bit
        $daclOffset  = unpack('V', $data, 16)[1]; // little endian unsigned 32 bit

        if ($ownerOffset > 0) {
            $sddl->setOwner(SID::fromBytes($data, $ownerOffset));
        }
        if ($groupOffset > 0) {
            $sddl->setGroup(SID::fromBytes($data, $groupOffset));
        }
        if ($saclOffset > 0) {
            $sddl->setSACL(ACL::fromBytes($data, $saclOffset));
        }
        if ($daclOffset > 0) {
            $sddl->setDACL(ACL::fromBytes($data, $daclOffset));
        }

        return $sddl;
    }

    public function toBytes(): string
    {
        $startOffset = 20;

        if ($this->sacl) {
            $saclOffset = $startOffset;
            $sacl = $this->sacl->toBytes();
            $startOffset += strlen($sacl);
        } else {
            $saclOffset = 0;
            $sacl = '';
        }

        if ($this->dacl) {
            $daclOffset = $startOffset;
            $dacl = $this->dacl->toBytes();
            $startOffset += strlen($dacl);
        } else {
            $daclOffset = 0;
            $dacl = '';
        }

        if ($this->owner) {
            $ownerOffset = $startOffset;
            $owner = $this->owner->getBinaryForm();
            $startOffset += strlen($owner);
        } else {
            $ownerOffset = 0;
            $owner = '';
        }

        if ($this->group) {
            $groupOffset = $startOffset;
            $group = $this->group->getBinaryForm();
        } else {
            $groupOffset = 0;
            $group = '';
        }

        return pack('C2vV4', 1, 0, $this->ctrlFlags, $ownerOffset, $groupOffset, $saclOffset, $daclOffset)
            . $sacl . $dacl . $owner . $group;
    }

    public function setDACL(?ACL $dacl): self
    {
        if ($dacl) {
            $this->ctrlFlags |= self::FLAG_DACL_PRESENT;
        } else {
            $this->ctrlFlags &= ~self::FLAG_DACL_PRESENT;
        }
        $this->dacl = $dacl;
        return $this;
    }
    public function getDACL(): ?ACL
    {
        return $this->dacl;
    }

    public function setSACL(?ACL $sacl): self
    {
        if ($sacl) {
            $this->ctrlFlags |= self::FLAG_SACL_PRESENT;
        } else {
            $this->ctrlFlags &= ~self::FLAG_SACL_PRESENT;
        }
        $this->sacl = $sacl;
        return $this;
    }
    public function getSACL(): ?ACL
    {
        return $this->sacl;
    }

    public function setOwner(?SID $owner): self
    {
        if ($owner) {
            $this->ctrlFlags &= ~self::FLAG_OWNER_DEFAULTED;
        } else {
            $this->ctrlFlags |= self::FLAG_OWNER_DEFAULTED;
        }
        $this->owner = $owner;
        return $this;
    }
    public function getOwner(): ?SID
    {
        return $this->owner;
    }

    public function setGroup(?SID $group): self
    {
        if ($group) {
            $this->ctrlFlags &= ~self::FLAG_GROUP_DEFAULTED;
        } else {
            $this->ctrlFlags |= self::FLAG_GROUP_DEFAULTED;
        }
        $this->group = $group;
        return $this;
    }
    public function getGroup(): ?SID
    {
        return $this->group;
    }

    public function setControllFlags(int $flags): self
    {
        assert($flags >= 0 && $flags < self::FLAG_SELF_RELATIVE * 2);

        $this->ctrlFlags = $flags;
        return $this;
    }
    public function getControlFlags(): int
    {
        return $this->ctrlFlags;
    }

    public const FLAG_OWNER_DEFAULTED = 1;
    public const FLAG_GROUP_DEFAULTED = 2;
    public const FLAG_DACL_PRESENT = 4;
    public const FLAG_DACL_DEFAULTED = 8;
    public const FLAG_SACL_PRESENT = 16;
    public const FLAG_SACL_DEFAULTED = 32;
    public const FLAG_SERVER_SECURITY = 64;
    public const FLAG_DACL_TRUSTED = 128;
    public const FLAG_DACL_INHERITANCE_REQ = 256;
    public const FLAG_INHERITANCE_REQ = 512;
    public const FLAG_DACL_AUTO_INHERIT = 1024;
    public const FLAG_SACL_AUTO_INHERIT = 2048;
    public const FLAG_DACL_PROTECTED = 4096;
    public const FLAG_SACL_PROTECTED = 8192;
    public const FLAG_CONTROL_VALID = 16384;
    public const FLAG_SELF_RELATIVE = 32768;

    protected int $ctrlFlags = 0;
    protected ?SID $owner = null;
    protected ?SID $group = null;
    protected ?ACL $sacl = null;
    protected ?ACL $dacl = null;
}
