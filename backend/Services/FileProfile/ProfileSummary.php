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
 * Immutable value object for the summary block of a file identity card.
 *
 * Array shape:
 *   created_at, created_by, last_modified_at, last_modified_by,
 *   event_count, comment_count
 *
 * created_at/created_by come from the first known audit event for the file
 * identity; last_modified_at/last_modified_by come from the newest event.
 * They are null when the file has no audit history yet. event_count and
 * comment_count are total counts, not page sizes.
 */
class ProfileSummary implements \JsonSerializable
{
    protected $createdAt;

    protected $createdBy;

    protected $lastModifiedAt;

    protected $lastModifiedBy;

    protected $eventCount;

    protected $commentCount;

    public function __construct(
        ?string $createdAt,
        ?string $createdBy,
        ?string $lastModifiedAt,
        ?string $lastModifiedBy,
        int $eventCount,
        int $commentCount
    ) {
        $this->createdAt = $createdAt;
        $this->createdBy = $createdBy;
        $this->lastModifiedAt = $lastModifiedAt;
        $this->lastModifiedBy = $lastModifiedBy;
        $this->eventCount = $eventCount;
        $this->commentCount = $commentCount;
    }

    /**
     * Hydrate from an aggregation row. Missing optional keys become null.
     */
    public static function fromArray(array $row): self
    {
        return new self(
            isset($row['created_at']) ? (string) $row['created_at'] : null,
            isset($row['created_by']) ? (string) $row['created_by'] : null,
            isset($row['last_modified_at']) ? (string) $row['last_modified_at'] : null,
            isset($row['last_modified_by']) ? (string) $row['last_modified_by'] : null,
            isset($row['event_count']) ? (int) $row['event_count'] : 0,
            isset($row['comment_count']) ? (int) $row['comment_count'] : 0
        );
    }

    public function getCreatedAt(): ?string
    {
        return $this->createdAt;
    }

    public function getCreatedBy(): ?string
    {
        return $this->createdBy;
    }

    public function getLastModifiedAt(): ?string
    {
        return $this->lastModifiedAt;
    }

    public function getLastModifiedBy(): ?string
    {
        return $this->lastModifiedBy;
    }

    public function getEventCount(): int
    {
        return $this->eventCount;
    }

    public function getCommentCount(): int
    {
        return $this->commentCount;
    }

    public function toArray(): array
    {
        return [
            'created_at' => $this->createdAt,
            'created_by' => $this->createdBy,
            'last_modified_at' => $this->lastModifiedAt,
            'last_modified_by' => $this->lastModifiedBy,
            'event_count' => $this->eventCount,
            'comment_count' => $this->commentCount,
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
