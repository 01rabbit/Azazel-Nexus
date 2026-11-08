"""ID -> Japanese display text for deterministic guidance (Nexus display layer).

The English canonical text comes from M.I.O.; an ID not listed here is shown in English.
The wording keeps the safety meaning of the English text: reports are unverified, checks are
read-only within existing authority, nothing is executed.
"""

DISPLAY_JA = {'sections': {'summary': '要約',
              'report_points': '報告の要点（供給された報告の記述。独立検証はされていない）',
              'required_checks': '必須の確認（既存権限内・read-only、自動実行・通知送信なし）',
              'key_unknowns': '重要な不明点',
              'details': '詳細',
              'explanations': '競合する説明（いずれも未検証。報告 ref に基づく候補であり、ref が内容を証明するものではない）',
              'weakening': 'どの説明を支持・弱めるか（観測条件）',
              'optional_checks': '必要時の追加確認',
              'all_unknowns': 'わかっていないこと（出典つき）',
              'weights': '新情報による確認優先度の変化（報告ベース・未検証）',
              'handoff': '引継ぎ用 ID'},
 'fact_kinds': {'supplied_report': '報告の観測値',
                'supplied_report_gap': '報告が欠落・不明と述べる点',
                'supplied_report_note': '報告の注記',
                'edge_decision': 'Edge の判断',
                'knowledge': 'Knowledge'},
 'sources': {'report': '報告',
             'frame': 'frame（呼出し元）',
             'frame_analysis': 'frame 解析（MIO）',
             'knowledge': 'Knowledge'},
 'playbooks': {'dns-resolution-degradation-v1': {'label': '名前解決の劣化報告（単一 vantage）',
                                                 'slots': {'resolver_or_path_degradation': '対象 resolver '
                                                                                           'または名前解決経路の劣化',
                                                           'probe_specific_or_partial_link': 'probe '
                                                                                             '側の見え方または部分的な回線劣化'},
                                                 'precondition_check': 'q4',
                                                 'checks': {'q1': '同時間帯の既存 DNS 監視記録で、他 probe→同じ resolver '
                                                                  'と、この probe→他 resolver の timeout を比較する（1 '
                                                                  'probe・1 resolver では原因と範囲は確定できない）',
                                                            'q2': '最新の集計窓で timeout が続いているかを見て、同時間帯の '
                                                                  'TCP と service 到達記録が正常かを確認する',
                                                            'q3': '承認済み変更記録と resolver／回線ログを異常期間と照合する',
                                                            'q4': '監視時計の同期と集計窓を確認してから前期間と比較する'},
                                                 'weakening': ['他 probe→同じ resolver で timeout、他 resolver は正常 '
                                                               '→ その resolver 固有の問題を指す',
                                                               'この probe→複数 resolver で timeout、他 probe では無し '
                                                               '→ probe 側または共有経路を指す',
                                                               '複数 probe→複数 resolver で同じ timeout → '
                                                               '共有経路・上流の条件を指す',
                                                               '同時間帯の TCP と service 到達が正常 → 全面断は支持されない'],
                                                 'boundaries': ['単一 vantage の報告を障害や原因の確定として扱わない',
                                                                'resolver・回線・設定の変更を提案しない',
                                                                '可用性の保護を優先する']},
               'auth-ambiguity-v1': {'label': '認証失敗の増加報告',
                                     'slots': {'credential_attack': '資格情報への攻撃（不正な認証試行）',
                                               'misconfigured_automation': '承認済み automation の再試行・設定不備'},
                                     'checks': {'q1': '認可済み read-only '
                                                      'の認証アラート表示で、失敗の後に成功ログインがあったかを確認する（アカウント・送信元が frame '
                                                      'に無ければ不明のまま）',
                                                'q2': '観測時刻・件数を、文書化された承認済み '
                                                      'automation／監視の基準と比較する（基準が無ければその欠落を記録し、意図を推定しない）'},
                                     'weakening': ['観測時刻・件数に一致する承認済み automation 基準があれば攻撃説が弱まる',
                                                   'frame は送信元・成功アクセス・ホスト影響を示さない'],
                                     'boundaries': ['主体や意図を断定しない', '推奨を実行可能として扱わない']},
               'generic-evidence-first-v1': {'label': '汎用（根拠優先）',
                                             'slots': {'hostile_activity': '敵対的活動',
                                                       'benign_activity': '良性・設定起因の活動',
                                                       'insufficient_evidence': '区別する根拠が不足'},
                                             'checks': {'q1': '既存の read-only 記録で、主たる訴えの時間窓（開始時刻・現在も続くか・深刻度）を先に確定する（個々の手がかりを比べる前に）',
                                                        'q2': '報告にある他のログ行の時刻を、その時間窓と突き合わせ、重なるものだけを関連ありとして扱う'},
                                             'weakening': [],
                                             'boundaries': []}},
 'topics': {'auth_success': '失敗後の成功認証が報告されている（成功後の活動を含め攻撃説の確認を先に）',
            'auth_baseline': '承認済み automation・credential 変更が報告されている',
            'auth_identity': 'アカウント・送信元が報告されている',
            'auth_impact': 'ホスト影響・権限変更が報告されている',
            'dns_other_sites': '他拠点の状況が報告されている',
            'dns_other_sites_negative': '他拠点では timeout なしと報告されている（probe 側・部分的な回線の説明を先に確認）',
            'dns_other_sites_positive': '他拠点でも timeout と報告されている（共有経路・resolver 側の説明を先に確認）',
            'dns_continuation': '継続・回復が報告されている',
            'dns_change': '変更・保守が報告されている'},
 'fixed_unknowns': {'Situation question and context are untrusted reports': '状況の問いと文脈は未検証の報告として扱う'},
 # Edge's own decision word, not an interface role; spelled indirectly so the retired-role check stays strict.
 'edge_values': {'Observe'.lower(): '経過観察', 'not_executed': '未実行'},
 'nochange': {'no_topic': '新情報なし（報告に該当する新しい観測の記述がない）',
              'no_effect': '新情報はあるが、確認優先度への影響なし',
              'compare': '比較条件が揃わないため、優先度を変えない'},
 'compare_unknown': 'Comparison conditions (window, time zone, aggregation) are not aligned',
 'directions': {'verification_priority_up': '確認の優先度が上がる', 'verification_priority_down': '確認の優先度が下がる'}}
