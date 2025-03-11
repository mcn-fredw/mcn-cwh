<?php

namespace McnCwh\Handler;

use Aws\CloudWatchLogs\CloudWatchLogsClient;
use Aws\CloudWatchLogs\Exception\CloudWatchLogsException;
use Monolog\Formatter\FormatterInterface;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Logger;

class CloudWatch extends AbstractProcessingHandler
{
    /**
     * @var CloudWatchLogsClient
     */
    protected $client;

    /**
     * @var string
     */
    protected $group;

    /**
     * @var string
     */
    protected $stream;

    /**
     * @var integer
     */
    protected $retention;

    /**
     * @var int
     */
    protected $batchSize;

    /**
     * @var array
     */
    protected $buffer = [];

    /**
     * @var array
     */
    protected $tags = [];

    /**
     * @var bool
     */
    protected $createGroup;

    /**
     * Data amount limit (http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html)
     *
     * @var int
     */
    protected $dataAmountLimit = 1048576;

    /**
     * @var int
     */
    protected $currentDataAmount = 0;

    /**
     * @var int
     */
    protected $remainingRequests = self::RPS_LIMIT;

    /**
     * @var int|null
     */
    protected $earliestTimestamp = null;

    /**
     * CloudWatchLogs constructor.
     * @param CloudWatchLogsClient $client
     *
     *  Log group names must be unique within a region for an AWS account.
     *  Log group names can be between 1 and 512 characters long.
     *  Log group names consist of the following characters: a-z, A-Z, 0-9, '_' (underscore), '-' (hyphen),
     * '/' (forward slash), and '.' (period).
     * @param string $group
     *
     *  Log stream names must be unique within the log group.
     *  Log stream names can be between 1 and 512 characters long.
     *  The ':' (colon) and '*' (asterisk) characters are not allowed.
     * @param string $stream
     *
     * @param int $retention
     * @param int $batchSize
     * @param array $tags
     * @param int $level
     * @param bool $bubble
     * @param bool $createGroup
     *
     * @throws \Exception
     */
    public function __construct(
        CloudWatchLogsClient $client,
        $group,
        $stream,
        $retention = 14,
        $batchSize = 10000,
        array $tags = [],
        $level = Logger::DEBUG,
        $bubble = true,
        $createGroup = true
    ) {
        if ($batchSize > 10000) {
            throw new \InvalidArgumentException(static::SIZE_ERROR_STR);
        }

        $this->client = $client;
        $this->group = $group;
        $this->stream = $stream;
        $this->retention = $retention;
        $this->batchSize = $batchSize;
        $this->tags = $tags;
        $this->createGroup = $createGroup;

        parent::__construct($level, $bubble);
    }

    /**
     * {@inheritdoc}
     */
    protected function write(array $record): void
    {
        $records = $this->formatRecords($record);

        foreach ($records as $record) {
            if ($this->willMessageSizeExceedLimit($record) || $this->willMessageTimestampExceedLimit($record)) {
                $this->flushBuffer();
            }

            $this->addToBuffer($record);

            if (count($this->buffer) >= $this->batchSize) {
                $this->flushBuffer();
            }
        }
    }

    /**
     * @param array $record
     */
    protected function addToBuffer(array $record): void
    {
        $this->currentDataAmount += $this->getMessageSize($record);

        $timestamp = $record[static::TIMESTAMP_STR];

        if (!$this->earliestTimestamp || $timestamp < $this->earliestTimestamp) {
            $this->earliestTimestamp = $timestamp;
        }

        $this->buffer[] = $record;
    }

    protected function flushBuffer(): void
    {
        if (!empty($this->buffer)) {

            // send items
            $this->send($this->buffer);

            // clear buffer
            $this->buffer = [];

            // clear the earliest timestamp
            $this->earliestTimestamp = null;

            // clear data amount
            $this->currentDataAmount = 0;
        }
    }

    /**
     * http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
     *
     * @param array $record
     * @return int
     */
    protected function getMessageSize($record): int
    {
        return strlen($record[static::MESSAGE_STR]) + 26;
    }

    /**
     * Determine whether the specified record's message size in addition to the
     * size of the current queued messages will exceed AWS CloudWatch's limit.
     *
     * @param array $record
     * @return bool
     */
    protected function willMessageSizeExceedLimit(array $record): bool
    {
        return $this->currentDataAmount + $this->getMessageSize($record) >= $this->dataAmountLimit;
    }

    /**
     * Determine whether the specified record's timestamp exceeds the 24 hour timespan limit
     * for all batched messages written in a single call to PutLogEvents.
     *
     * @param array $record
     * @return bool
     */
    protected function willMessageTimestampExceedLimit(array $record): bool
    {
        return $this->earliestTimestamp && $record[static::TIMESTAMP_STR] - $this->earliestTimestamp > self::TIMESPAN_LIMIT;
    }

    /**
     * Event size in the batch can not be bigger than 256 KB
     * https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html
     *
     * @param array $entry
     * @return array
     */
    protected function formatRecords(array $entry): array
    {
        $entries = str_split($entry[static::FORMATTED_STR], self::EVENT_SIZE_LIMIT);
        $timestamp = $entry[static::DATETIME_STR]->format(static::MILLISECONDS_FORMAT_STR) * 1000;
        $records = [];

        foreach ($entries as $entry) {
            $records[] = [
                static::MESSAGE_STR => $entry,
                static::TIMESTAMP_STR => $timestamp
            ];
        }

        return $records;
    }

    /**
     * The batch of events must satisfy the following constraints:
     *  - The maximum batch size is 1,048,576 bytes, and this size is calculated as the sum of all event messages in
     * UTF-8, plus 26 bytes for each log event.
     *  - None of the log events in the batch can be more than 2 hours in the future.
     *  - None of the log events in the batch can be older than 14 days or the retention period of the log group.
     *  - The log events in the batch must be in chronological ordered by their timestamp (the time the event occurred,
     * expressed as the number of milliseconds since Jan 1, 1970 00:00:00 UTC).
     *  - The maximum number of log events in a batch is 10,000.
     *  - A batch of log events in a single request cannot span more than 24 hours. Otherwise, the operation fails.
     *
     * @param array $entries
     *
     * @throws \Aws\CloudWatchLogs\Exception\CloudWatchLogsException Thrown by putLogEvents for example in case of an
     *                                                               invalid sequence token
     */
    protected function send(array& $entries, bool $retry = true): void
    {
        $data = [
            static::LOG_GROUP_NAME_STR => $this->group,
            static::LOG_STREAM_NAME_STR => $this->stream,
            static::LOG_EVENTS_STR => $entries
        ];

        try {
            $response = $this->client->putLogEvents($data);
        } catch (CloudWatchLogsException $ex) {
            $m = $ex->getAwsErrorMessage();
            if ($retry && !is_null($m) && strstr($m, static::RES_NOT_FOUND_STR) !== false) {
                $this->initializeGroup();
                $this->send($entries, false);
            } else {
                $stderr = fopen(static::PHP_STDERR_STR, static::W_STR);
                fprintf($stderr, 'CRITICAL log to %s/%s = %s', $this->group, $this->stream, $m);
                fclose($stderr);
            }
        }
    }

    protected function initializeGroup(): void
    {
        try {
            $createLogGroupArguments = [static::LOG_GROUP_NAME_STR => $this->group];
            
            if (!empty($this->tags)) {
                $createLogGroupArguments[static::TAGS_STR] = $this->tags;
            }
            
            $this->client->createLogGroup($createLogGroupArguments);
            
            if ($this->retention !== null) {
                $policy = [
                    static::LOG_GROUP_NAME_STR => $this->group,
                    static::RETENTION_STR => $this->retention,
                ];
                $this->client->putRetentionPolicy($policy);
            }
        } catch (Exception $ex) {
            $stderr = fopen(static::PHP_STDERR_STR, static::W_STR);
            fprintf($stderr, 'CRITICAL create %s = %s', $this->group, $ex->getMessage());
            fclose($stderr);
        }
    }

    /**
     * String constants.
     */
    const DATETIME_STR = 'datetime';
    const FORMATTED_STR = 'formatted';
    const LOG_EVENTS_STR = 'logEvents';
    const LOG_GROUP_NAME_STR = 'logGroupName';
    const LOG_STREAM_NAME_STR = 'logStreamName';
    const MESSAGE_STR = 'message';
    const MILLISECONDS_FORMAT_STR = 'U.u';
    const PHP_STDERR_STR = 'php://stderr';
    const RES_NOT_FOUND_STR =  'ResourceNotFoundException';
    const RETENTION_STR = 'retentionInDays';
    const SIZE_ERROR_STR = 'Batch size can not be greater than 10000';
    const TAGS_STR = 'tags';
    const TIMESTAMP_STR = 'timestamp';
    const W_STR = 'w';
    
    /**
     * Requests per second limit (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html)
     */
    const RPS_LIMIT = 5;
    
    /**
     * Event size limit (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html)
     *
     * @var int
     */
    const EVENT_SIZE_LIMIT = 262118; // 262144 - reserved 26
    
    /**
     * The batch of log events in a single PutLogEvents request cannot span more than 24 hours.
     *
     * @var int
     */
    const TIMESPAN_LIMIT = 86400000;
}
