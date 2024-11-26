<?php declare(strict_types=1);

namespace Tine\SDDL_Parser;

class ACE
{
    public function __construct(
        protected string $binaryForm,
        protected int $flags = 0,
        protected int $type = -1
    ){}

    public function toBytes(): string
    {
        return $this->binaryForm;
    }

    public function getType(): int
    {
        return $this->type;
    }

    public function setType(int $type): self
    {
        throw new ParserException('not implemented');
    }

    public function setFlags(int $flags): self
    {
        throw new ParserException('not implemented');
    }

    public static function fromBytes(string $data, int $offset): self
    {
        $dataLen = strlen($data);
        if ($dataLen < $offset + 4) {
            throw new ParserException('failed parsing ACE, not enough data remaining');
        }

        $aceType = unpack('C', $data, $offset)[1]; // one character
        $aceSize = unpack('v', $data, $offset + 2)[1]; // little endian unsigned 16 bit

        if (0 === $aceSize || 0 !== ($aceSize % 4)) {
            throw new ParserException('bad ACE size: ' . $aceSize);
        }

        if ($dataLen < $offset + $aceSize) {
            throw new ParserException('failed parsing ACE, not enough data remaining');
        }

        switch ($aceType) {
            case self::ACETYPE_ACCESS_ALLOWED:
            case self::ACETYPE_ACCESS_DENIED:
            case self::ACETYPE_SYSTEM_AUDIT:
            case self::ACETYPE_SYSTEM_MANDATORY_LABEL:
            case self::ACETYPE_SYSTEM_SCOPED_POLICY_ID:
                return ACE\AccessMask::fromBytes($data, $offset);

            case self::ACETYPE_ACCESS_ALLOWED_OBJECT:
            case self::ACETYPE_ACCESS_DENIED_OBJECT:
                return ACE\ObjectAccess::fromBytes($data, $offset);

            case self::ACETYPE_SYSTEM_ALARM:
            case self::ACETYPE_ACCESS_ALLOWED_COMPOUND:
            case self::ACETYPE_SYSTEM_AUDIT_OBJECT:
            case self::ACETYPE_SYSTEM_ALARM_OBJECT:
            case self::ACETYPE_ACCESS_ALLOWED_CALLBACK:
            case self::ACETYPE_ACCESS_DENIED_CALLBACK:
            case self::ACETYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
            case self::ACETYPE_ACCESS_DENIED_CALLBACK_OBJECT:
            case self::ACETYPE_SYSTEM_AUDIT_CALLBACK:
            case self::ACETYPE_SYSTEM_ALARM_CALLBACK:
            case self::ACETYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
            case self::ACETYPE_SYSTEM_ALARM_CALLBACK_OBJECT:
            case self::ACETYPE_SYSTEM_RESOURCE_ATTRIBUTE:
                return new ACE(substr($data, $offset, $aceSize));
            default:
                throw new ParserException('unknown ACE type: ' . $aceType);
        }
    }

    public const ACETYPE_ACCESS_ALLOWED = 0;
    public const ACETYPE_ACCESS_DENIED = 1;
    public const ACETYPE_SYSTEM_AUDIT = 2;
    public const ACETYPE_SYSTEM_ALARM = 3;
    public const ACETYPE_ACCESS_ALLOWED_COMPOUND = 4;
    public const ACETYPE_ACCESS_ALLOWED_OBJECT = 5;
    public const ACETYPE_ACCESS_DENIED_OBJECT = 6;
    public const ACETYPE_SYSTEM_AUDIT_OBJECT = 7;
    public const ACETYPE_SYSTEM_ALARM_OBJECT = 8;
    public const ACETYPE_ACCESS_ALLOWED_CALLBACK = 9;
    public const ACETYPE_ACCESS_DENIED_CALLBACK = 10;
    public const ACETYPE_ACCESS_ALLOWED_CALLBACK_OBJECT = 11;
    public const ACETYPE_ACCESS_DENIED_CALLBACK_OBJECT = 12;
    public const ACETYPE_SYSTEM_AUDIT_CALLBACK = 13;
    public const ACETYPE_SYSTEM_ALARM_CALLBACK = 14;
    public const ACETYPE_SYSTEM_AUDIT_CALLBACK_OBJECT = 15;
    public const ACETYPE_SYSTEM_ALARM_CALLBACK_OBJECT = 16;
    public const ACETYPE_SYSTEM_MANDATORY_LABEL = 17;
    public const ACETYPE_SYSTEM_RESOURCE_ATTRIBUTE = 18;
    public const ACETYPE_SYSTEM_SCOPED_POLICY_ID = 19;

    public const ACE_OBJECT_TYPE_PRESENT = 1;
    public const ACE_INHERITED_OBJECT_TYPE_PRESENT = 2;

    public const ACCESS_MASK_GENERIC_READ            = 0x80000000;
    public const ACCESS_MASK_GENERIC_WRITE           = 0x40000000;
    public const ACCESS_MASK_GENERIC_EXECUTE         = 0x20000000;
    public const ACCESS_MASK_GENERIC_ALL             = 0x10000000;
    public const ACCESS_MASK_MAXIMUM_ALLOWED         = 0x02000000;
    public const ACCESS_MASK_ACCESS_SYSTEM_SECURITY  = 0x01000000;
    public const ACCESS_MASK_SYNCHRONIZE             = 0x00100000;
    public const ACCESS_MASK_WRITE_OWNER             = 0x00080000;
    public const ACCESS_MASK_WRITE_DACL              = 0x00040000;
    public const ACCESS_MASK_READ_CONTROL            = 0x00020000;
    public const ACCESS_MASK_DELETE                  = 0x00010000;
    public const ACCESS_MASK_ADS_RIGHT_DS_CREATE_CHILD    = 0x00000001;
    public const ACCESS_MASK_ADS_RIGHT_DS_DELETE_CHILD    = 0x00000002;
    public const ACCESS_MASK_ADS_RIGHT_DS_LIST_CONTENTS   = 0x00000004;
    public const ACCESS_MASK_ADS_RIGHT_DS_SELF            = 0x00000008;
    public const ACCESS_MASK_ADS_RIGHT_DS_READ_PROP       = 0x00000010;
    public const ACCESS_MASK_ADS_RIGHT_DS_WRITE_PROP      = 0x00000020;
    public const ACCESS_MASK_ADS_RIGHT_DS_DELETE_TREE     = 0x00000040;
    public const ACCESS_MASK_ADS_RIGHT_DS_LIST_OBJECT     = 0x00000080;
    public const ACCESS_MASK_ADS_RIGHT_DS_CONTROL_ACCESS  = 0x00000100;
}