<?php declare(strict_types=1);

namespace Tine\SDDL_Parser;

class ACL
{
    public function __construct(
        protected int $version
    ) {
        assert($version === 2 || $version === 4);
    }

    public static function fromBytes(string $data, int $offset): self
    {
        $dataLen = strlen($data);
        if ($dataLen < $offset + 8) {
            throw new ParserException('failed parsing ACL, not enough data remaining');
        }

        $header = unpack('C2', $data, $offset); // two characters
        if ($header[1] !== 2 && $header[1] !== 4) {
            throw new ParserException('ACL byte one expected to be 2 or 4: ' . $header[1]);
        }
        if ($header[2] !== 0) {
            throw new ParserException('ACL byte two expected to be 0: ' . $header[2]);
        }

        $aclSize = unpack('v', $data, $offset + 2)[1]; // little endian unsigned 16 bit
        $aceCount = unpack('v', $data, $offset + 4)[1]; // little endian unsigned 16 bit

        if ($dataLen < $offset + $aclSize) {
            throw new ParserException('failed parsing ACL, not enough data remaining');
        }

        if (0 !== unpack('v', $data, $offset + 6)[1]) { // little endian unsigned 16 bit
            throw new ParserException('ACL byte seven and eight expected to be 0: ' . unpack('v', $data, $offset + 6)[1]);
        }


        $acl = new ACL($header[1]);

        $aceOffset = $offset + 8;
        for ($i = 0; $i < $aceCount; ++$i) {
            $acl->addACE($ace = ACE::fromBytes($data, $aceOffset));

            // TODO FIXME!
            $aceOffset += strlen($ace->toBytes());
        }

        return $acl;
    }

    public function getACEs(): array
    {
        return $this->ace;
    }

    public function removeACE(int $offset): self
    {
        unset($this->ace[$offset]);
        return $this;
    }

    public function addACE(ACE $ace): self
    {
        $this->ace[] = $ace;
        return $this;
    }

    public function toBytes(): string
    {
        $bytes = '';
        foreach($this->ace as $ace) {
            $bytes .= $ace->toBytes();
        }

        return pack('C2v3', $this->version, 0, strlen($bytes) + 8, count($this->ace), 0) . $bytes;
    }

    /**
     * @var array<int, ACE>
     */
    protected array $ace = [];
}