<?php
declare(strict_types=1);

namespace App\Core;

/**
 * 계정 정지 목록 확인 (BOLA 대응, 2026-11-10)
 *
 * response/playbooks/suspend_account.yml 이 쓰는 TSV 파일을 읽는다.
 *   형식(한 줄 = 한 계정): user_id <TAB> 해제시각(epoch 초) <TAB> 사유
 *   예) 7	1762760000	bola rule 100931 alert 1762750000.1
 *
 * 설치: 이 파일을 web/src/src/Core/AccountGuard.php 로 복사하고,
 *       인증 직후 두 곳(v2 AuthMiddleware, v1 index.php)에서 isSuspended() 를 부른다 — account_guard.patch
 *
 * 파일이 없거나 읽기에 실패하면 "정지 없음"(fail-open)으로 본다.
 * 이유: 대응 쪽 파일 문제 하나로 전체 로그인이 막히지 않게. 정지는 보조 수단이고 근본 해결은 소유권 검사다.
 */
final class AccountGuard
{
    /** @var string */
    private $file;

    public function __construct(?string $file = null)
    {
        $env = getenv('SUSPENDED_USERS_FILE');
        $this->file = $file ?? (($env !== false && $env !== '') ? $env : __DIR__ . '/../../logs/suspended_users.tsv');
    }

    public function isSuspended(int $userId, ?int $now = null): bool
    {
        $now = $now ?? time();
        if (!is_readable($this->file)) {
            return false;
        }
        $fh = @fopen($this->file, 'r');
        if ($fh === false) {
            return false;
        }
        try {
            while (($line = fgets($fh)) !== false) {
                $cols = explode("\t", rtrim($line, "\r\n"));
                if (count($cols) < 2 || !ctype_digit($cols[0]) || !ctype_digit($cols[1])) {
                    continue;   // 형식이 틀린 줄은 무시
                }
                if ((int) $cols[0] === $userId && (int) $cols[1] > $now) {
                    return true;
                }
            }
        } finally {
            fclose($fh);
        }
        return false;
    }
}
