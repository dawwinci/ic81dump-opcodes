<?php

$licenseSalt = 'CLIENT_ABC_2026';

function dk()
{
    global $licenseSalt;
    return hash('sha256', $licenseSalt);
}

// @ioncube.dynamickey dk() -> "118ae040018ffd55edf1bbbcf3ee01c43dd8d588fb02fb39832ddf8c5225389b" RANDOM
function premiumFeature()
{
    echo "Dynamic Key function executed successfully";
}

premiumFeature();