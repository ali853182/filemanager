<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Milos Stojanovic <alcalbg@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE file
 */

namespace Filegator\Services\FileProfile;

/**
 * Immutable value object for one row of the files identity table.
 *
 * Array shape (also returned by repository methods):
 *   file_id, path, path_key, type, created_at, updated_at,
 *   deleted_at, copied_from_file_id
 *
 * path_key is the lowercased normalized path used for Windows
 * case-insensitive lookup. deleted_at is null for active identities.
 * copied_from_file_id is set only on copies.
 */
class FileIdentity implements \JsonSerializable
{
    protected $fileId;

    protected $path;

    protected $pathKey;

    protected $type;

    protected $createdAt;

    protected $updatedAt;

    protected $deletedAt;

    protected $copiedFromFileId;

    public function __construct(
        string $fileId,
        string $path,
        string $pathKey,
        string $type,
        string $createdAt,
        string $updatedAt,
        ?string $deletedAt = null,
        ?string $copiedFromFileId = null
    ) {
        if ($fileId === '') {
            throw new \InvalidArgumentException('FileIdentity requires a non-empty file_id.');
        }

        if (! in_array($type, ['file', 'dir'], true)) {
            throw new \InvalidArgumentException('FileIdentity type must be "file" or "dir".');
        }

        $this->fileId = $fileId;
        $this->path = $path;
        $this->pathKey = $pathKey;
        $this->type = $type;
        $this->createdAt = $createdAt;
        $this->updatedAt = $updatedAt;
        $this->deletedAt = $deletedAt;
        $this->copiedFromFileId = $copiedFromFileId;
    }

    /**
     * Hydrate from a repository row.
     */
    public static function fromArray(array $row): self
    {
        foreach (['file_id', 'path', 'path_key', 'type', 'created_at', 'updated_at'] as $key) {
            if (! isset($row[$key])) {
                throw new \InvalidArgumentException('FileIdentity is missing required key: '.$key);
            }
        }

        return new self(
            (string) $row['file_id'],
            (string) $row['path'],
            (string) $row['path_key'],
            (string) $row['type'],
            (string) $row['created_at'],
            (string) $row['updated_at'],
            isset($row['deleted_at']) ? (string) $row['deleted_at'] : null,
            isset($row['copied_from_file_id']) ? (string) $row['copied_from_file_id'] : null
        );
    }

    public function getFileId(): string
    {
        return $this->fileId;
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function getPathKey(): string
    {
        return $this->pathKey;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getCreatedAt(): string
    {
        return $this->createdAt;
    }

    public function getUpdatedAt(): string
    {
        return $this->updatedAt;
    }

    public function getDeletedAt(): ?string
    {
        return $this->deletedAt;
    }

    public function getCopiedFromFileId(): ?string
    {
        return $this->copiedFromFileId;
    }

    public function isDeleted(): bool
    {
        return $this->deletedAt !== null;
    }

    public function toArray(): array
    {
        return [
            'file_id' => $this->fileId,
            'path' => $this->path,
            'path_key' => $this->pathKey,
            'type' => $this->type,
            'created_at' => $this->createdAt,
            'updated_at' => $this->updatedAt,
            'deleted_at' => $this->deletedAt,
            'copied_from_file_id' => $this->copiedFromFileId,
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
