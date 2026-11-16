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
 * Immutable value object for one row of the comments table.
 *
 * Array shape (also returned by repository methods):
 *   comment_id, file_id, user, role, body, created_at, updated_at, deleted_at
 *
 * body is plain text (1-5000 characters after trimming) and must never be
 * rendered as HTML or copied into an audit event. updated_at is reserved for a
 * future edit feature and is null in v1. deleted_at is set on soft delete.
 */
class Comment implements \JsonSerializable
{
    protected $commentId;

    protected $fileId;

    protected $user;

    protected $role;

    protected $body;

    protected $createdAt;

    protected $updatedAt;

    protected $deletedAt;

    public function __construct(
        int $commentId,
        string $fileId,
        string $user,
        string $role,
        string $body,
        string $createdAt,
        ?string $updatedAt = null,
        ?string $deletedAt = null
    ) {
        $this->commentId = $commentId;
        $this->fileId = $fileId;
        $this->user = $user;
        $this->role = $role;
        $this->body = $body;
        $this->createdAt = $createdAt;
        $this->updatedAt = $updatedAt;
        $this->deletedAt = $deletedAt;
    }

    /**
     * Hydrate from a repository row.
     */
    public static function fromArray(array $row): self
    {
        foreach (['comment_id', 'file_id', 'user', 'role', 'body', 'created_at'] as $key) {
            if (! isset($row[$key])) {
                throw new \InvalidArgumentException('Comment is missing required key: '.$key);
            }
        }

        return new self(
            (int) $row['comment_id'],
            (string) $row['file_id'],
            (string) $row['user'],
            (string) $row['role'],
            (string) $row['body'],
            (string) $row['created_at'],
            isset($row['updated_at']) ? (string) $row['updated_at'] : null,
            isset($row['deleted_at']) ? (string) $row['deleted_at'] : null
        );
    }

    public function getCommentId(): int
    {
        return $this->commentId;
    }

    public function getFileId(): string
    {
        return $this->fileId;
    }

    public function getUser(): string
    {
        return $this->user;
    }

    public function getRole(): string
    {
        return $this->role;
    }

    public function getBody(): string
    {
        return $this->body;
    }

    public function getCreatedAt(): string
    {
        return $this->createdAt;
    }

    public function getUpdatedAt(): ?string
    {
        return $this->updatedAt;
    }

    public function getDeletedAt(): ?string
    {
        return $this->deletedAt;
    }

    public function isDeleted(): bool
    {
        return $this->deletedAt !== null;
    }

    public function toArray(): array
    {
        return [
            'comment_id' => $this->commentId,
            'file_id' => $this->fileId,
            'user' => $this->user,
            'role' => $this->role,
            'body' => $this->body,
            'created_at' => $this->createdAt,
            'updated_at' => $this->updatedAt,
            'deleted_at' => $this->deletedAt,
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
